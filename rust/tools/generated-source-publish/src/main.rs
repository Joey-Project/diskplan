#![cfg(target_os = "macos")]

use std::env;
use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

const RENAME_SWAP: u32 = 0x0000_0002;
const RENAME_EXCL: u32 = 0x0000_0004;
static STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

unsafe extern "C" {
    fn renameatx_np(
        from_fd: libc::c_int,
        from: *const libc::c_char,
        to_fd: libc::c_int,
        to: *const libc::c_char,
        flags: libc::c_uint,
    ) -> libc::c_int;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AccessState {
    mode: libc::mode_t,
    owner: libc::uid_t,
    group: libc::gid_t,
    flags: u32,
}

struct FileSeal {
    handle: File,
    identity: Identity,
    access: AccessState,
    bytes: Vec<u8>,
}

struct Target {
    directory: File,
    display_path: PathBuf,
    name: CString,
    source_bytes: Vec<u8>,
    stage_name: Option<CString>,
    staged: Option<FileSeal>,
    previous: Option<FileSeal>,
    published: bool,
}

impl Target {
    fn prepare(repo_root: &Path, source: &Path, destination: &Path) -> Result<Self, String> {
        let source_metadata = fs::symlink_metadata(source).map_err(|error| {
            format!(
                "generated source unavailable at {}: {error}",
                source.display()
            )
        })?;
        if source_metadata.file_type().is_symlink() || !source_metadata.file_type().is_file() {
            return Err(format!(
                "generated source is not a regular non-symlink file: {}",
                source.display()
            ));
        }
        let source_bytes = fs::read(source).map_err(|error| {
            format!(
                "failed to read generated source {}: {error}",
                source.display()
            )
        })?;

        let parent = validate_destination(repo_root, destination)?;
        let directory = File::open(&parent).map_err(|error| {
            format!(
                "failed to open destination directory {}: {error}",
                parent.display()
            )
        })?;
        validate_open_directory(&directory, &parent)?;
        let name =
            path_component_cstring(destination.file_name().ok_or_else(|| {
                format!("destination has no file name: {}", destination.display())
            })?)?;
        let previous = open_optional_sealed_slot(directory.as_raw_fd(), &name, destination)?;

        Ok(Self {
            directory,
            display_path: destination.to_path_buf(),
            name,
            source_bytes,
            stage_name: None,
            staged: None,
            previous,
            published: false,
        })
    }

    fn verify(&self) -> Result<(), String> {
        let bytes = read_regular_slot(self.directory.as_raw_fd(), &self.name, &self.display_path)?;
        if bytes != self.source_bytes {
            return Err(format!(
                "generated source differs from tracked destination: {}",
                self.display_path.display()
            ));
        }
        Ok(())
    }

    fn stage(&mut self) -> Result<(), String> {
        let stage_name = create_stage_name(&self.name)?;
        let mut stage =
            open_new_stage(self.directory.as_raw_fd(), &stage_name).map_err(|error| {
                format!(
                    "failed to create same-directory stage for {}: {error}",
                    self.display_path.display()
                )
            })?;
        self.stage_name = Some(stage_name.clone());
        stage
            .write_all(&self.source_bytes)
            .and_then(|()| stage.flush())
            .and_then(|()| stage.sync_all())
            .map_err(|error| {
                format!(
                    "failed to write and fsync stage for {}: {error}",
                    self.display_path.display()
                )
            })?;
        stage
            .set_permissions(fs::Permissions::from_mode(0o644))
            .and_then(|()| stage.sync_all())
            .map_err(|error| {
                format!(
                    "failed to set and fsync stage permissions for {}: {error}",
                    self.display_path.display()
                )
            })?;
        stage.seek(SeekFrom::Start(0)).map_err(|error| {
            format!(
                "failed to rewind stage for {}: {error}",
                self.display_path.display()
            )
        })?;
        let mut verified = Vec::new();
        stage.read_to_end(&mut verified).map_err(|error| {
            format!(
                "failed to verify stage for {}: {error}",
                self.display_path.display()
            )
        })?;
        if verified != self.source_bytes {
            return Err(format!(
                "staged bytes failed verification for {}",
                self.display_path.display()
            ));
        }
        self.directory.sync_all().map_err(|error| {
            format!(
                "failed to fsync destination directory {}: {error}",
                self.display_path.display()
            )
        })?;
        let seal = FileSeal::capture(stage, &self.display_path)?;
        seal.validate_slot(
            self.directory.as_raw_fd(),
            &stage_name,
            &self.display_path,
            "staged generated source",
        )?;
        self.staged = Some(seal);
        Ok(())
    }

    fn publish(&mut self) -> Result<(), String> {
        let stage_name = self
            .stage_name
            .as_ref()
            .ok_or_else(|| "internal error: target was not staged".to_owned())?;
        let staged = self
            .staged
            .as_ref()
            .ok_or_else(|| "internal error: target has no staged-file seal".to_owned())?;
        staged.validate_slot(
            self.directory.as_raw_fd(),
            stage_name,
            &self.display_path,
            "staged generated source",
        )?;
        match self.previous.as_ref() {
            Some(previous) => previous.validate_slot(
                self.directory.as_raw_fd(),
                &self.name,
                &self.display_path,
                "previous destination",
            )?,
            None => ensure_slot_missing(
                self.directory.as_raw_fd(),
                &self.name,
                &self.display_path,
                "new destination",
            )?,
        }

        let flags = if self.previous.is_some() {
            RENAME_SWAP
        } else {
            RENAME_EXCL
        };
        rename_slot(self.directory.as_raw_fd(), stage_name, &self.name, flags).map_err(
            |error| {
                format!(
                    "atomic publish failed for {}: {error}",
                    self.display_path.display()
                )
            },
        )?;
        self.published = true;
        staged.validate_slot(
            self.directory.as_raw_fd(),
            &self.name,
            &self.display_path,
            "published generated source",
        )?;
        if let Some(previous) = self.previous.as_ref() {
            previous.validate_slot(
                self.directory.as_raw_fd(),
                stage_name,
                &self.display_path,
                "rollback backup",
            )?;
        }
        let post_publish = self.directory.sync_all().map_err(|error| {
            format!(
                "failed to fsync published directory for {}: {error}",
                self.display_path.display()
            )
        });
        let post_publish = post_publish.and_then(|()| self.verify());
        if let Err(error) = post_publish {
            return match self.rollback() {
                Ok(()) => Err(format!("{error}; this destination was rolled back")),
                Err(rollback_error) => Err(format!(
                    "{error}; this destination rollback was incomplete: {rollback_error}"
                )),
            };
        }
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), String> {
        if !self.published {
            return Err("internal error: target was not published".to_owned());
        }
        let published = self
            .staged
            .as_ref()
            .ok_or_else(|| "internal error: published target has no file seal".to_owned())?;
        published.validate_slot(
            self.directory.as_raw_fd(),
            &self.name,
            &self.display_path,
            "published generated source",
        )?;
        match self.previous.as_ref() {
            Some(previous) => {
                let stage_name = self.stage_name.as_ref().ok_or_else(|| {
                    "internal error: previous destination has no rollback slot".to_owned()
                })?;
                previous.validate_slot(
                    self.directory.as_raw_fd(),
                    stage_name,
                    &self.display_path,
                    "rollback backup",
                )?;
                rename_slot(
                    self.directory.as_raw_fd(),
                    stage_name,
                    &self.name,
                    RENAME_SWAP,
                )
                .map_err(|error| {
                    format!("failed to restore {}: {error}", self.display_path.display())
                })?;
                previous.validate_slot(
                    self.directory.as_raw_fd(),
                    &self.name,
                    &self.display_path,
                    "restored destination",
                )?;
                published.validate_slot(
                    self.directory.as_raw_fd(),
                    stage_name,
                    &self.display_path,
                    "rolled-back generated source",
                )?;
                unlink_sealed_slot(
                    self.directory.as_raw_fd(),
                    stage_name,
                    &self.display_path,
                    "rolled-back generated source",
                    published,
                )
                .map_err(|error| {
                    format!(
                        "restored {} but failed to remove rollback stage: {error}",
                        self.display_path.display()
                    )
                })?;
            }
            None => unlink_sealed_slot(
                self.directory.as_raw_fd(),
                &self.name,
                &self.display_path,
                "newly published destination",
                published,
            )
            .map_err(|error| {
                format!(
                    "failed to remove newly published destination {}: {error}",
                    self.display_path.display()
                )
            })?,
        }
        self.directory.sync_all().map_err(|error| {
            format!(
                "failed to fsync rollback directory for {}: {error}",
                self.display_path.display()
            )
        })?;
        self.stage_name = None;
        self.staged = None;
        self.published = false;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), String> {
        if !self.published {
            return Err("internal error: target was not published".to_owned());
        }
        let published = self
            .staged
            .as_ref()
            .ok_or_else(|| "internal error: published target has no file seal".to_owned())?;
        published.validate_slot(
            self.directory.as_raw_fd(),
            &self.name,
            &self.display_path,
            "published generated source",
        )?;
        if let (Some(previous), Some(stage_name)) =
            (self.previous.as_ref(), self.stage_name.as_ref())
        {
            unlink_sealed_slot(
                self.directory.as_raw_fd(),
                stage_name,
                &self.display_path,
                "rollback backup",
                previous,
            )
            .map_err(|error| {
                format!(
                    "failed to remove previous generated source backup for {}: {error}",
                    self.display_path.display()
                )
            })?;
        }
        self.directory.sync_all().map_err(|error| {
            format!(
                "failed to fsync completed destination directory for {}: {error}",
                self.display_path.display()
            )
        })?;
        self.stage_name = None;
        self.staged = None;
        self.previous = None;
        self.published = false;
        Ok(())
    }

    fn discard_stage(&mut self) -> Result<(), String> {
        if !self.published
            && let (Some(stage_name), Some(staged)) =
                (self.stage_name.as_ref(), self.staged.as_ref())
        {
            unlink_sealed_slot(
                self.directory.as_raw_fd(),
                stage_name,
                &self.display_path,
                "staged generated source",
                staged,
            )?;
            self.directory.sync_all().map_err(|error| {
                format!(
                    "failed to fsync discarded stage directory for {}: {error}",
                    self.display_path.display()
                )
            })?;
            self.stage_name = None;
            self.staged = None;
        }
        Ok(())
    }
}

impl FileSeal {
    fn capture(mut handle: File, display_path: &Path) -> Result<Self, String> {
        let (identity, access) = inspect_open_regular_file(&handle, display_path)?;
        let bytes = read_open_file(&mut handle, display_path)?;
        let (verified_identity, verified_access) =
            inspect_open_regular_file(&handle, display_path)?;
        if verified_identity != identity {
            return Err(format!(
                "open file identity changed while sealing {}: expected {identity:?}, found {verified_identity:?}",
                display_path.display()
            ));
        }
        if verified_access != access {
            return Err(format!(
                "open file access state changed while sealing {}: expected {access:?}, found {verified_access:?}",
                display_path.display()
            ));
        }
        Ok(Self {
            handle,
            identity,
            access,
            bytes,
        })
    }

    fn validate_slot(
        &self,
        directory_fd: RawFd,
        name: &CString,
        display_path: &Path,
        role: &str,
    ) -> Result<(), String> {
        self.validate_handle(display_path, role)?;
        let mut opened = open_existing_slot(directory_fd, name, display_path, role)?;
        let (identity, access) = inspect_open_regular_file(&opened, display_path)?;
        if identity != self.identity {
            return Err(format!(
                "{role} pathname identity mismatched at {}: expected {:?}, found {identity:?}",
                display_path.display(),
                self.identity
            ));
        }
        if access != self.access {
            return Err(format!(
                "{role} access state mismatched at {}: expected {:?}, found {access:?}",
                display_path.display(),
                self.access
            ));
        }
        let bytes = read_open_file(&mut opened, display_path)?;
        if bytes != self.bytes {
            return Err(format!(
                "{role} content mismatched at {}",
                display_path.display()
            ));
        }
        let pathname_identity = slot_identity(directory_fd, name, display_path)?;
        if pathname_identity != Some(self.identity) {
            return Err(format!(
                "{role} pathname changed during inspection at {}: expected {:?}, found {pathname_identity:?}",
                display_path.display(),
                self.identity
            ));
        }
        Ok(())
    }

    fn validate_handle(&self, display_path: &Path, role: &str) -> Result<(), String> {
        let (identity, access) = inspect_open_regular_file(&self.handle, display_path)?;
        if identity != self.identity {
            return Err(format!(
                "{role} sealed handle identity mismatched at {}: expected {:?}, found {identity:?}",
                display_path.display(),
                self.identity
            ));
        }
        if access != self.access {
            return Err(format!(
                "{role} sealed handle access state mismatched at {}: expected {:?}, found {access:?}",
                display_path.display(),
                self.access
            ));
        }
        let mut handle = self.handle.try_clone().map_err(|error| {
            format!(
                "failed to duplicate sealed handle for {role} at {}: {error}",
                display_path.display()
            )
        })?;
        let bytes = read_open_file(&mut handle, display_path)?;
        if bytes != self.bytes {
            return Err(format!(
                "{role} sealed content mismatched at {}",
                display_path.display()
            ));
        }
        Ok(())
    }
}

fn validate_destination(repo_root: &Path, destination: &Path) -> Result<PathBuf, String> {
    if !repo_root.is_absolute() {
        return Err(format!(
            "repository root is not absolute: {}",
            repo_root.display()
        ));
    }
    let relative = destination.strip_prefix(repo_root).map_err(|_| {
        format!(
            "destination is outside repository root {}: {}",
            repo_root.display(),
            destination.display()
        )
    })?;
    let repo_root = fs::canonicalize(repo_root).map_err(|error| {
        format!(
            "failed to canonicalize repository root {}: {error}",
            repo_root.display()
        )
    })?;
    if !destination.is_absolute() {
        return Err(format!(
            "destination is not absolute: {}",
            destination.display()
        ));
    }
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "destination contains a non-normal path component: {}",
            destination.display()
        ));
    }

    let parent_relative = relative.parent().ok_or_else(|| {
        format!(
            "destination has no parent inside repository: {}",
            destination.display()
        )
    })?;
    let mut current = repo_root;
    for component in parent_relative.components() {
        let Component::Normal(component) = component else {
            return Err(format!(
                "invalid destination component: {}",
                destination.display()
            ));
        };
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|error| {
            format!(
                "destination directory unavailable at {}: {error}",
                current.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err(format!(
                "destination directory is not a real directory: {}",
                current.display()
            ));
        }
    }
    Ok(current)
}

fn validate_open_directory(directory: &File, expected: &Path) -> Result<(), String> {
    let mut bytes = vec![0_u8; libc::PATH_MAX as usize];
    let result = unsafe {
        libc::fcntl(
            directory.as_raw_fd(),
            libc::F_GETPATH,
            bytes.as_mut_ptr().cast::<libc::c_char>(),
        )
    };
    if result == -1 {
        return Err(format!(
            "failed to resolve open destination directory {}: {}",
            expected.display(),
            std::io::Error::last_os_error()
        ));
    }
    let actual = unsafe { CStr::from_ptr(bytes.as_ptr().cast::<libc::c_char>()) };
    let actual = PathBuf::from(std::ffi::OsString::from_vec(actual.to_bytes().to_vec()));
    if actual != expected {
        return Err(format!(
            "destination directory identity changed; expected {}, opened {}",
            expected.display(),
            actual.display()
        ));
    }
    Ok(())
}

fn path_component_cstring(component: &OsStr) -> Result<CString, String> {
    CString::new(component.as_bytes()).map_err(|_| "path contains an interior NUL byte".to_owned())
}

fn create_stage_name(destination_name: &CString) -> Result<CString, String> {
    let counter = STAGE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut bytes = destination_name.as_bytes().to_vec();
    bytes.extend_from_slice(format!(".diskplan-stage.{}.{}", process::id(), counter).as_bytes());
    CString::new(bytes).map_err(|_| "stage name contains an interior NUL byte".to_owned())
}

fn open_new_stage(directory_fd: RawFd, name: &CString) -> std::io::Result<File> {
    let fd = unsafe {
        libc::openat(
            directory_fd,
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )
    };
    if fd == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn open_optional_sealed_slot(
    directory_fd: RawFd,
    name: &CString,
    display_path: &Path,
) -> Result<Option<FileSeal>, String> {
    let expected_identity = match slot_identity(directory_fd, name, display_path)? {
        Some(identity) => identity,
        None => return Ok(None),
    };
    let handle = open_existing_slot(directory_fd, name, display_path, "previous destination")?;
    let seal = FileSeal::capture(handle, display_path)?;
    if seal.identity != expected_identity {
        return Err(format!(
            "previous destination pathname identity changed while opening {}: expected {expected_identity:?}, found {:?}",
            display_path.display(),
            seal.identity
        ));
    }
    seal.validate_slot(directory_fd, name, display_path, "previous destination")?;
    Ok(Some(seal))
}

fn open_existing_slot(
    directory_fd: RawFd,
    name: &CString,
    display_path: &Path,
    role: &str,
) -> Result<File, String> {
    let fd = unsafe {
        libc::openat(
            directory_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW,
        )
    };
    if fd == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Err(format!("{role} is missing at {}", display_path.display()));
        }
        return Err(format!(
            "{role} is unreadable or failed inspection at {}: {error}",
            display_path.display()
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn inspect_open_regular_file(
    file: &File,
    display_path: &Path,
) -> Result<(Identity, AccessState), String> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstat(file.as_raw_fd(), metadata.as_mut_ptr()) };
    if result == -1 {
        return Err(format!(
            "failed to inspect open file {}: {}",
            display_path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(format!(
            "opened file is not regular: {}",
            display_path.display()
        ));
    }
    Ok((
        Identity {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        },
        AccessState {
            mode: metadata.st_mode & 0o7777,
            owner: metadata.st_uid,
            group: metadata.st_gid,
            flags: metadata.st_flags,
        },
    ))
}

fn read_open_file(file: &mut File, display_path: &Path) -> Result<Vec<u8>, String> {
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        format!(
            "failed to rewind open file {}: {error}",
            display_path.display()
        )
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        format!(
            "failed to read open file {}: {error}",
            display_path.display()
        )
    })?;
    Ok(bytes)
}

fn ensure_slot_missing(
    directory_fd: RawFd,
    name: &CString,
    display_path: &Path,
    role: &str,
) -> Result<(), String> {
    match slot_identity(directory_fd, name, display_path)? {
        None => Ok(()),
        Some(identity) => Err(format!(
            "{role} pathname is occupied at {} by {identity:?}",
            display_path.display()
        )),
    }
}

fn unlink_sealed_slot(
    directory_fd: RawFd,
    name: &CString,
    display_path: &Path,
    role: &str,
    seal: &FileSeal,
) -> Result<(), String> {
    seal.validate_slot(directory_fd, name, display_path, role)?;
    unlink_slot(directory_fd, name).map_err(|error| {
        format!(
            "failed to unlink sealed {role} at {}: {error}",
            display_path.display()
        )
    })
}

fn slot_identity(
    directory_fd: RawFd,
    name: &CString,
    display_path: &Path,
) -> Result<Option<Identity>, String> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            directory_fd,
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(format!(
            "failed to inspect destination pathname slot {}: {error}",
            display_path.display()
        ));
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(format!(
            "destination pathname slot is not a regular file: {}",
            display_path.display()
        ));
    }
    Ok(Some(Identity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    }))
}

fn read_regular_slot(
    directory_fd: RawFd,
    name: &CString,
    display_path: &Path,
) -> Result<Vec<u8>, String> {
    slot_identity(directory_fd, name, display_path)?.ok_or_else(|| {
        format!(
            "tracked generated source is missing: {}",
            display_path.display()
        )
    })?;
    let fd = unsafe {
        libc::openat(
            directory_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW,
        )
    };
    if fd == -1 {
        return Err(format!(
            "failed to open tracked generated source {}: {}",
            display_path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata().map_err(|error| {
        format!(
            "failed to inspect open destination {}: {error}",
            display_path.display()
        )
    })?;
    if !metadata.file_type().is_file() {
        return Err(format!(
            "opened destination is not a regular file: {}",
            display_path.display()
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        format!(
            "failed to read tracked generated source {}: {error}",
            display_path.display()
        )
    })?;
    Ok(bytes)
}

fn rename_slot(
    directory_fd: RawFd,
    from: &CString,
    to: &CString,
    flags: u32,
) -> std::io::Result<()> {
    let result = unsafe {
        renameatx_np(
            directory_fd,
            from.as_ptr(),
            directory_fd,
            to.as_ptr(),
            flags,
        )
    };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn unlink_slot(directory_fd: RawFd, name: &CString) -> std::io::Result<()> {
    let result = unsafe { libc::unlinkat(directory_fd, name.as_ptr(), 0) };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn parse_pairs(arguments: &[String]) -> Result<(PathBuf, Vec<(PathBuf, PathBuf)>), String> {
    if arguments.len() < 3 || !(arguments.len() - 1).is_multiple_of(2) {
        return Err(
            "usage: generated-source-publish <verify|publish> <repo-root> <source> <destination> [<source> <destination> ...]"
                .to_owned(),
        );
    }
    let repo_root = PathBuf::from(&arguments[0]);
    let mut pairs = Vec::new();
    for pair in arguments[1..].chunks_exact(2) {
        pairs.push((PathBuf::from(&pair[0]), PathBuf::from(&pair[1])));
    }
    Ok((repo_root, pairs))
}

fn run(arguments: &[String]) -> Result<(), String> {
    let (command, remainder) = arguments
        .split_first()
        .ok_or_else(|| "missing command".to_owned())?;
    let (repo_root, pairs) = parse_pairs(remainder)?;
    let mut targets = Vec::new();
    for (source, destination) in pairs {
        if targets
            .iter()
            .any(|target: &Target| target.display_path == destination)
        {
            return Err(format!("duplicate destination: {}", destination.display()));
        }
        targets.push(Target::prepare(&repo_root, &source, &destination)?);
    }

    match command.as_str() {
        "verify" => {
            for target in &targets {
                target.verify()?;
            }
        }
        "publish" => {
            for target in &mut targets {
                if let Err(error) = target.stage() {
                    let mut cleanup_errors = Vec::new();
                    for staged in &mut targets {
                        if let Err(cleanup_error) = staged.discard_stage() {
                            cleanup_errors.push(cleanup_error);
                        }
                    }
                    if cleanup_errors.is_empty() {
                        return Err(error);
                    }
                    return Err(format!(
                        "{error}; staged-file cleanup was incomplete: {}",
                        cleanup_errors.join("; ")
                    ));
                }
            }
            for index in 0..targets.len() {
                if let Err(error) = targets[index].publish() {
                    let mut rollback_errors = Vec::new();
                    if targets[index].published
                        && let Err(rollback_error) = targets[index].rollback()
                    {
                        rollback_errors.push(rollback_error);
                    }
                    for published in targets[..index].iter_mut().rev() {
                        if let Err(rollback_error) = published.rollback() {
                            rollback_errors.push(rollback_error);
                        }
                    }
                    for staged in &mut targets[index..] {
                        if let Err(cleanup_error) = staged.discard_stage() {
                            rollback_errors.push(cleanup_error);
                        }
                    }
                    if rollback_errors.is_empty() {
                        return Err(format!(
                            "{error}; previously published files were rolled back"
                        ));
                    }
                    return Err(format!(
                        "{error}; rollback was incomplete: {}",
                        rollback_errors.join("; ")
                    ));
                }
            }
            for target in &mut targets {
                target.finish()?;
            }
        }
        _ => return Err(format!("unsupported command: {command}")),
    }
    Ok(())
}

fn main() {
    let arguments: Vec<String> = env::args().skip(1).collect();
    if let Err(error) = run(&arguments) {
        eprintln!("generated-source-publish: {error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stage_path(directory: &Path, target: &Target) -> PathBuf {
        let name = target.stage_name.as_ref().expect("stage name");
        directory.join(std::ffi::OsString::from_vec(name.as_bytes().to_vec()))
    }

    fn prepared_existing_target(root: &Path) -> (PathBuf, Target) {
        let directory = root.join("generated");
        fs::create_dir(&directory).expect("create directory");
        let source = root.join("source");
        let destination = directory.join("output");
        fs::write(&source, b"new bytes").expect("write source");
        fs::write(&destination, b"old bytes").expect("write destination");
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644))
            .expect("set destination permissions");
        let target = Target::prepare(root, &source, &destination).expect("prepare target");
        (directory, target)
    }

    #[test]
    fn publishes_and_verifies_existing_and_missing_targets() {
        let root = tempfile::tempdir().expect("create root");
        let first_directory = root.path().join("first");
        let second_directory = root.path().join("second");
        fs::create_dir_all(&first_directory).expect("create first directory");
        fs::create_dir_all(&second_directory).expect("create second directory");
        let first_source = root.path().join("first.source");
        let second_source = root.path().join("second.source");
        let first_destination = first_directory.join("generated.swift");
        let second_destination = second_directory.join("generated.rs");
        fs::write(&first_source, b"new swift").expect("write first source");
        fs::write(&second_source, b"new rust").expect("write second source");
        fs::write(&first_destination, b"old swift").expect("write destination");

        let arguments = vec![
            "publish".to_owned(),
            root.path().display().to_string(),
            first_source.display().to_string(),
            first_destination.display().to_string(),
            second_source.display().to_string(),
            second_destination.display().to_string(),
        ];
        run(&arguments).expect("publish generated sources");
        assert_eq!(
            fs::read(&first_destination).expect("read first"),
            b"new swift"
        );
        assert_eq!(
            fs::read(&second_destination).expect("read second"),
            b"new rust"
        );

        let mut verify_arguments = arguments;
        verify_arguments[0] = "verify".to_owned();
        run(&verify_arguments).expect("verify generated sources");
    }

    #[test]
    fn rejects_destination_symlink() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("create root");
        let directory = root.path().join("generated");
        fs::create_dir(&directory).expect("create directory");
        let source = root.path().join("source");
        let outside = root.path().join("outside");
        let destination = directory.join("output");
        fs::write(&source, b"generated").expect("write source");
        fs::write(&outside, b"outside").expect("write outside");
        symlink(&outside, &destination).expect("create symlink");

        let error = run(&[
            "publish".to_owned(),
            root.path().display().to_string(),
            source.display().to_string(),
            destination.display().to_string(),
        ])
        .expect_err("reject symlink");
        assert!(error.contains("not a regular file"), "{error}");
        assert_eq!(fs::read(&outside).expect("read outside"), b"outside");
    }

    #[test]
    fn rejects_symlinked_destination_directory() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("create root");
        let real_directory = root.path().join("real");
        let linked_directory = root.path().join("linked");
        fs::create_dir(&real_directory).expect("create directory");
        symlink(&real_directory, &linked_directory).expect("create directory symlink");
        let source = root.path().join("source");
        fs::write(&source, b"generated").expect("write source");

        let error = run(&[
            "publish".to_owned(),
            root.path().display().to_string(),
            source.display().to_string(),
            linked_directory.join("output").display().to_string(),
        ])
        .expect_err("reject directory symlink");
        assert!(error.contains("not a real directory"), "{error}");
        assert!(!real_directory.join("output").exists());
    }

    #[test]
    fn rollback_restores_previous_bytes_after_publication() {
        let root = tempfile::tempdir().expect("create root");
        let directory = root.path().join("generated");
        fs::create_dir(&directory).expect("create directory");
        let source = root.path().join("source");
        let destination = directory.join("output");
        fs::write(&source, b"new bytes").expect("write source");
        fs::write(&destination, b"old bytes").expect("write destination");

        let mut target =
            Target::prepare(root.path(), &source, &destination).expect("prepare target");
        target.stage().expect("stage target");
        target.publish().expect("publish target");
        assert_eq!(
            fs::read(&destination).expect("read new bytes"),
            b"new bytes"
        );
        target.rollback().expect("roll back target");
        assert_eq!(
            fs::read(&destination).expect("read old bytes"),
            b"old bytes"
        );
    }

    #[test]
    fn rollback_rejects_replaced_backup_without_swapping_or_unlinking_it() {
        let root = tempfile::tempdir().expect("create root");
        let (directory, mut target) = prepared_existing_target(root.path());
        let destination = directory.join("output");
        target.stage().expect("stage target");
        target.publish().expect("publish target");
        let backup = stage_path(&directory, &target);
        let parked_backup = directory.join("parked-backup");
        fs::rename(&backup, &parked_backup).expect("park real backup");
        fs::write(&backup, b"interloper").expect("replace backup pathname");

        let error = target
            .rollback()
            .expect_err("reject replaced rollback backup");

        assert!(error.contains("pathname identity mismatched"), "{error}");
        assert_eq!(
            fs::read(&destination).expect("read destination"),
            b"new bytes"
        );
        assert_eq!(fs::read(&backup).expect("read interloper"), b"interloper");
        assert_eq!(
            fs::read(&parked_backup).expect("read parked backup"),
            b"old bytes"
        );
    }

    #[test]
    fn rollback_rejects_in_place_backup_content_mutation() {
        let root = tempfile::tempdir().expect("create root");
        let (directory, mut target) = prepared_existing_target(root.path());
        let destination = directory.join("output");
        target.stage().expect("stage target");
        target.publish().expect("publish target");
        let backup = stage_path(&directory, &target);
        fs::write(&backup, b"bad bytes").expect("mutate backup in place");

        let error = target
            .rollback()
            .expect_err("reject mutated rollback backup");

        assert!(error.contains("sealed content mismatched"), "{error}");
        assert_eq!(
            fs::read(&destination).expect("read destination"),
            b"new bytes"
        );
        assert_eq!(
            fs::read(&backup).expect("read mutated backup"),
            b"bad bytes"
        );
    }

    #[test]
    fn rollback_rejects_backup_access_state_mutation() {
        let root = tempfile::tempdir().expect("create root");
        let (directory, mut target) = prepared_existing_target(root.path());
        let destination = directory.join("output");
        target.stage().expect("stage target");
        target.publish().expect("publish target");
        let backup = stage_path(&directory, &target);
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o600))
            .expect("change backup permissions");

        let error = target
            .rollback()
            .expect_err("reject changed rollback backup access state");

        assert!(error.contains("access state mismatched"), "{error}");
        assert_eq!(
            fs::read(&destination).expect("read destination"),
            b"new bytes"
        );
        assert_eq!(fs::read(&backup).expect("read backup"), b"old bytes");
    }

    #[test]
    fn finish_rejects_replaced_backup_without_unlinking_it() {
        let root = tempfile::tempdir().expect("create root");
        let (directory, mut target) = prepared_existing_target(root.path());
        let destination = directory.join("output");
        target.stage().expect("stage target");
        target.publish().expect("publish target");
        let backup = stage_path(&directory, &target);
        let parked_backup = directory.join("parked-backup");
        fs::rename(&backup, &parked_backup).expect("park real backup");
        fs::write(&backup, b"interloper").expect("replace backup pathname");

        let error = target.finish().expect_err("reject replaced finish backup");

        assert!(error.contains("pathname identity mismatched"), "{error}");
        assert_eq!(
            fs::read(&destination).expect("read destination"),
            b"new bytes"
        );
        assert_eq!(fs::read(&backup).expect("read interloper"), b"interloper");
        assert_eq!(
            fs::read(&parked_backup).expect("read parked backup"),
            b"old bytes"
        );
    }

    #[test]
    fn discard_rejects_replaced_stage_without_unlinking_it() {
        let root = tempfile::tempdir().expect("create root");
        let (directory, mut target) = prepared_existing_target(root.path());
        target.stage().expect("stage target");
        let stage = stage_path(&directory, &target);
        let parked_stage = directory.join("parked-stage");
        fs::rename(&stage, &parked_stage).expect("park real stage");
        fs::write(&stage, b"interloper").expect("replace stage pathname");

        let error = target
            .discard_stage()
            .expect_err("reject replaced discard stage");

        assert!(error.contains("pathname identity mismatched"), "{error}");
        assert_eq!(fs::read(&stage).expect("read interloper"), b"interloper");
        assert_eq!(
            fs::read(&parked_stage).expect("read parked stage"),
            b"new bytes"
        );
    }

    #[test]
    fn later_publication_failure_rolls_back_an_earlier_target() {
        let root = tempfile::tempdir().expect("create root");
        let first_directory = root.path().join("first");
        let second_directory = root.path().join("second");
        fs::create_dir_all(&first_directory).expect("create first directory");
        fs::create_dir_all(&second_directory).expect("create second directory");
        let first_source = root.path().join("first.source");
        let second_source = root.path().join("second.source");
        let first_destination = first_directory.join("generated.swift");
        let second_destination = second_directory.join("generated.rs");
        fs::write(&first_source, b"new swift").expect("write first source");
        fs::write(&second_source, b"new rust").expect("write second source");
        fs::write(&first_destination, b"old swift").expect("write first destination");

        let mut first =
            Target::prepare(root.path(), &first_source, &first_destination).expect("prepare first");
        let mut second = Target::prepare(root.path(), &second_source, &second_destination)
            .expect("prepare second");
        first.stage().expect("stage first");
        second.stage().expect("stage second");
        first.publish().expect("publish first");

        fs::write(&second_destination, b"interloper").expect("occupy second pathname slot");
        second
            .publish()
            .expect_err("exclusive second publish must fail");
        first.rollback().expect("roll back first publish");
        second.discard_stage().expect("discard second stage");

        assert_eq!(
            fs::read(&first_destination).expect("read restored first"),
            b"old swift"
        );
        assert_eq!(
            fs::read(&second_destination).expect("read protected second"),
            b"interloper"
        );
    }

    #[test]
    fn rejects_non_regular_destination() {
        let root = tempfile::tempdir().expect("create root");
        let directory = root.path().join("generated");
        fs::create_dir(&directory).expect("create directory");
        let source = root.path().join("source");
        let destination = directory.join("output");
        fs::write(&source, b"generated").expect("write source");
        fs::create_dir(&destination).expect("create destination directory");

        let error = Target::prepare(root.path(), &source, &destination)
            .err()
            .expect("reject non-regular destination");
        assert!(error.contains("not a regular file"), "{error}");
    }
}
