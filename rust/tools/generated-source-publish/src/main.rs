#![cfg(target_os = "macos")]

#[cfg(test)]
use std::cell::Cell;
use std::env;
use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::path::{Component, Path, PathBuf};
use std::process;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

const RENAME_SWAP: u32 = 0x0000_0002;
const RENAME_EXCL: u32 = 0x0000_0004;
static STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);
static QUARANTINE_COUNTER: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
thread_local! {
    static FAIL_STAGE_AFTER_CREATE: Cell<bool> = const { Cell::new(false) };
    static MUTATE_QUARANTINE_AFTER_MOVE: Cell<bool> = const { Cell::new(false) };
}

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

#[derive(Clone, Debug, Eq, PartialEq)]
struct AccessState {
    mode: libc::mode_t,
    owner: libc::uid_t,
    group: libc::gid_t,
    flags: u32,
    extended_acl: Vec<u8>,
}

struct FileSeal {
    handle: File,
    identity: Identity,
    access: AccessState,
    bytes: Vec<u8>,
}

struct ProvisionalStage {
    handle: File,
    identity: Option<Identity>,
}

// Rename and unlink safety relies on this explicit namespace precondition, not on
// treating a pathname stat as an object-identity binding. The directory must be
// owned by this effective user, deny group/other writes, have no extended ACL,
// and remain under Diskplan's cooperative exclusive flock for the whole run.
struct DirectoryLease {
    handle: File,
    display_path: PathBuf,
    identity: Identity,
    access: AccessState,
}

impl Drop for DirectoryLease {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.handle.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl DirectoryLease {
    fn acquire(path: &Path) -> Result<Self, String> {
        let handle = File::open(path).map_err(|error| {
            format!(
                "failed to open destination directory {}: {error}",
                path.display()
            )
        })?;
        validate_open_directory(&handle, path)?;
        let (identity, access) = inspect_open_directory(&handle, path)?;
        enforce_trusted_directory_policy(path, &access)?;
        let result = unsafe { libc::flock(handle.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == -1 {
            return Err(format!(
                "destination directory is not cooperatively exclusive at {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            ));
        }
        let lease = Self {
            handle,
            display_path: path.to_path_buf(),
            identity,
            access,
        };
        lease.validate_exclusive_namespace()?;
        Ok(lease)
    }

    fn fd(&self) -> RawFd {
        self.handle.as_raw_fd()
    }

    fn validate_exclusive_namespace(&self) -> Result<(), String> {
        let (identity, access) = inspect_open_directory(&self.handle, &self.display_path)?;
        if identity != self.identity {
            return Err(format!(
                "exclusive destination directory identity changed at {}: expected {:?}, found {identity:?}",
                self.display_path.display(),
                self.identity
            ));
        }
        if access != self.access {
            return Err(format!(
                "exclusive destination directory access policy changed at {}: expected {:?}, found {access:?}",
                self.display_path.display(),
                self.access
            ));
        }
        enforce_trusted_directory_policy(&self.display_path, &access)
    }
}

struct Target {
    directory: Arc<DirectoryLease>,
    display_path: PathBuf,
    name: CString,
    source_bytes: Vec<u8>,
    stage_name: Option<CString>,
    provisional_stage: Option<ProvisionalStage>,
    staged: Option<FileSeal>,
    previous: Option<FileSeal>,
    published: bool,
}

impl Target {
    #[cfg(test)]
    fn prepare(repo_root: &Path, source: &Path, destination: &Path) -> Result<Self, String> {
        let parent = validate_destination(repo_root, destination)?;
        let directory = Arc::new(DirectoryLease::acquire(&parent)?);
        Self::prepare_with_directory(source, destination, directory)
    }

    fn prepare_with_directory(
        source: &Path,
        destination: &Path,
        directory: Arc<DirectoryLease>,
    ) -> Result<Self, String> {
        directory.validate_exclusive_namespace()?;
        let source_bytes = read_sealed_source(source)?;
        let name =
            path_component_cstring(destination.file_name().ok_or_else(|| {
                format!("destination has no file name: {}", destination.display())
            })?)?;
        let previous = open_optional_sealed_slot(directory.fd(), &name, destination)?;

        Ok(Self {
            directory,
            display_path: destination.to_path_buf(),
            name,
            source_bytes,
            stage_name: None,
            provisional_stage: None,
            staged: None,
            previous,
            published: false,
        })
    }

    fn verify(&self) -> Result<(), String> {
        self.directory.validate_exclusive_namespace()?;
        let bytes = read_regular_slot(self.directory.fd(), &self.name, &self.display_path)?;
        if bytes != self.source_bytes {
            return Err(format!(
                "generated source differs from tracked destination: {}",
                self.display_path.display()
            ));
        }
        Ok(())
    }

    fn stage(&mut self) -> Result<(), String> {
        self.directory.validate_exclusive_namespace()?;
        let stage_name = create_stage_name(&self.name)?;
        let stage = open_new_stage(self.directory.fd(), &stage_name).map_err(|error| {
            format!(
                "failed to create same-directory stage for {}: {error}",
                self.display_path.display()
            )
        })?;
        self.stage_name = Some(stage_name.clone());
        self.provisional_stage = Some(ProvisionalStage {
            handle: stage,
            identity: None,
        });
        let provisional_identity = inspect_open_regular_identity(
            &self
                .provisional_stage
                .as_ref()
                .ok_or_else(|| "internal error: provisional stage disappeared".to_owned())?
                .handle,
            &self.display_path,
        )?;
        self.provisional_stage
            .as_mut()
            .ok_or_else(|| "internal error: provisional stage disappeared".to_owned())?
            .identity = Some(provisional_identity);
        #[cfg(test)]
        if FAIL_STAGE_AFTER_CREATE.with(|flag| flag.replace(false)) {
            return Err(format!(
                "injected post-create pre-seal stage failure for {}",
                self.display_path.display()
            ));
        }
        let stage = &mut self
            .provisional_stage
            .as_mut()
            .ok_or_else(|| "internal error: provisional stage disappeared".to_owned())?
            .handle;
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
        self.directory.handle.sync_all().map_err(|error| {
            format!(
                "failed to fsync destination directory {}: {error}",
                self.display_path.display()
            )
        })?;
        let provisional = self
            .provisional_stage
            .as_ref()
            .ok_or_else(|| "internal error: provisional stage disappeared".to_owned())?;
        let seal = FileSeal::capture(
            provisional.handle.try_clone().map_err(|error| {
                format!(
                    "failed to duplicate provisional stage handle for {}: {error}",
                    self.display_path.display()
                )
            })?,
            &self.display_path,
        )?;
        if provisional
            .identity
            .is_some_and(|identity| seal.identity != identity)
        {
            return Err(format!(
                "staged file identity changed before sealing {}: expected {:?}, found {:?}",
                self.display_path.display(),
                provisional.identity,
                seal.identity
            ));
        }
        seal.validate_slot(
            self.directory.fd(),
            &stage_name,
            &self.display_path,
            "staged generated source",
        )?;
        self.provisional_stage = None;
        self.staged = Some(seal);
        Ok(())
    }

    fn publish(&mut self) -> Result<(), String> {
        self.directory.validate_exclusive_namespace()?;
        let stage_name = self
            .stage_name
            .as_ref()
            .ok_or_else(|| "internal error: target was not staged".to_owned())?;
        let staged = self
            .staged
            .as_ref()
            .ok_or_else(|| "internal error: target has no staged-file seal".to_owned())?;
        staged.validate_slot(
            self.directory.fd(),
            stage_name,
            &self.display_path,
            "staged generated source",
        )?;
        match self.previous.as_ref() {
            Some(previous) => previous.validate_slot(
                self.directory.fd(),
                &self.name,
                &self.display_path,
                "previous destination",
            )?,
            None => ensure_slot_missing(
                self.directory.fd(),
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
        rename_slot(self.directory.fd(), stage_name, &self.name, flags).map_err(|error| {
            format!(
                "atomic publish failed for {}: {error}",
                self.display_path.display()
            )
        })?;
        self.published = true;
        staged.validate_slot(
            self.directory.fd(),
            &self.name,
            &self.display_path,
            "published generated source",
        )?;
        if let Some(previous) = self.previous.as_ref() {
            previous.validate_slot(
                self.directory.fd(),
                stage_name,
                &self.display_path,
                "rollback backup",
            )?;
        }
        let post_publish = self.directory.handle.sync_all().map_err(|error| {
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
        self.directory.validate_exclusive_namespace()?;
        if !self.published {
            return Err("internal error: target was not published".to_owned());
        }
        let published = self
            .staged
            .as_ref()
            .ok_or_else(|| "internal error: published target has no file seal".to_owned())?;
        published.validate_slot(
            self.directory.fd(),
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
                    self.directory.fd(),
                    stage_name,
                    &self.display_path,
                    "rollback backup",
                )?;
                rename_slot(self.directory.fd(), stage_name, &self.name, RENAME_SWAP).map_err(
                    |error| format!("failed to restore {}: {error}", self.display_path.display()),
                )?;
                previous.validate_slot(
                    self.directory.fd(),
                    &self.name,
                    &self.display_path,
                    "restored destination",
                )?;
                published.validate_slot(
                    self.directory.fd(),
                    stage_name,
                    &self.display_path,
                    "rolled-back generated source",
                )?;
                quarantine_and_delete_sealed_slot(
                    &self.directory,
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
            None => quarantine_and_delete_sealed_slot(
                &self.directory,
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
        self.directory.handle.sync_all().map_err(|error| {
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
        self.directory.validate_exclusive_namespace()?;
        if !self.published {
            return Err("internal error: target was not published".to_owned());
        }
        let published = self
            .staged
            .as_ref()
            .ok_or_else(|| "internal error: published target has no file seal".to_owned())?;
        published.validate_slot(
            self.directory.fd(),
            &self.name,
            &self.display_path,
            "published generated source",
        )?;
        if let (Some(previous), Some(stage_name)) =
            (self.previous.as_ref(), self.stage_name.as_ref())
        {
            quarantine_and_delete_sealed_slot(
                &self.directory,
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
        self.directory.handle.sync_all().map_err(|error| {
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
        self.directory.validate_exclusive_namespace()?;
        if !self.published
            && let Some(stage_name) = self.stage_name.as_ref()
        {
            let provisional_seal;
            let staged = if let Some(staged) = self.staged.as_ref() {
                staged
            } else if let Some(provisional) = self.provisional_stage.as_ref() {
                provisional_seal = FileSeal::capture(
                    provisional.handle.try_clone().map_err(|error| {
                        format!(
                            "failed to duplicate provisional stage handle for cleanup at {}: {error}; recovery path: {}",
                            self.display_path.display(),
                            slot_display_path(&self.directory.display_path, stage_name).display()
                        )
                    })?,
                    &self.display_path,
                )
                .map_err(|error| {
                    format!(
                        "failed to seal provisional stage for cleanup at {}: {error}; recovery path: {}",
                        self.display_path.display(),
                        slot_display_path(&self.directory.display_path, stage_name).display()
                    )
                })?;
                if provisional
                    .identity
                    .is_some_and(|identity| provisional_seal.identity != identity)
                {
                    return Err(format!(
                        "provisional stage identity changed before cleanup at {}; recovery path: {}",
                        self.display_path.display(),
                        slot_display_path(&self.directory.display_path, stage_name).display()
                    ));
                }
                &provisional_seal
            } else {
                return Err(format!(
                    "stage exists without a held descriptor seal at {}; recovery path: {}",
                    self.display_path.display(),
                    slot_display_path(&self.directory.display_path, stage_name).display()
                ));
            };
            quarantine_and_delete_sealed_slot(
                &self.directory,
                stage_name,
                &self.display_path,
                "staged generated source",
                staged,
            )?;
            self.directory.handle.sync_all().map_err(|error| {
                format!(
                    "failed to fsync discarded stage directory for {}: {error}",
                    self.display_path.display()
                )
            })?;
            self.stage_name = None;
            self.provisional_stage = None;
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
        let verified_bytes = read_open_file(&mut handle, display_path)?;
        if verified_bytes != bytes {
            return Err(format!(
                "open file content changed while sealing {}",
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
    let repo_handle = File::open(&repo_root).map_err(|error| {
        format!(
            "failed to open repository root {}: {error}",
            repo_root.display()
        )
    })?;
    validate_open_directory(&repo_handle, &repo_root)?;
    let (_, repo_access) = inspect_open_directory(&repo_handle, &repo_root)?;
    enforce_trusted_directory_policy(&repo_root, &repo_access)?;
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

fn inspect_open_directory(
    directory: &File,
    display_path: &Path,
) -> Result<(Identity, AccessState), String> {
    let (identity, file_type, access) = inspect_open_object(directory, display_path)?;
    if file_type != libc::S_IFDIR {
        return Err(format!(
            "opened destination directory is not a directory: {}",
            display_path.display()
        ));
    }
    Ok((identity, access))
}

fn enforce_trusted_directory_policy(path: &Path, access: &AccessState) -> Result<(), String> {
    let effective_user = unsafe { libc::geteuid() };
    if access.owner != effective_user {
        return Err(format!(
            "destination directory is not owned by the effective user at {}: expected uid {effective_user}, found {}",
            path.display(),
            access.owner
        ));
    }
    if access.mode & 0o022 != 0 {
        return Err(format!(
            "destination directory permits group or other writes at {}: mode {:04o}",
            path.display(),
            access.mode
        ));
    }
    if !access.extended_acl.is_empty() {
        return Err(format!(
            "destination directory has an extended ACL and is not a trusted-exclusive namespace: {}",
            path.display()
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

fn create_quarantine_name(destination_name: &CString) -> Result<CString, String> {
    let counter = QUARANTINE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut bytes = destination_name.as_bytes().to_vec();
    bytes.extend_from_slice(
        format!(".diskplan-quarantine.{}.{}", process::id(), counter).as_bytes(),
    );
    CString::new(bytes).map_err(|_| "quarantine name contains an interior NUL byte".to_owned())
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

fn open_source_no_follow(source: &Path) -> Result<File, String> {
    let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        format!(
            "generated source path contains an interior NUL: {}",
            source.display()
        )
    })?;
    let fd = unsafe { libc::open(source.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW) };
    if fd == -1 {
        return Err(format!(
            "generated source is unavailable, unreadable, or a symlink at {}: {}",
            Path::new(OsStr::from_bytes(source.as_bytes())).display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_sealed_source(source: &Path) -> Result<Vec<u8>, String> {
    let handle = open_source_no_follow(source)?;
    FileSeal::capture(handle, source)
        .map(|seal| seal.bytes)
        .map_err(|error| {
            format!(
                "failed to seal generated source {}: {error}",
                source.display()
            )
        })
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
    let (identity, file_type, access) = inspect_open_object(file, display_path)?;
    if file_type != libc::S_IFREG {
        return Err(format!(
            "opened file is not regular: {}",
            display_path.display()
        ));
    }
    Ok((identity, access))
}

fn inspect_open_regular_identity(file: &File, display_path: &Path) -> Result<Identity, String> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstat(file.as_raw_fd(), metadata.as_mut_ptr()) };
    if result == -1 {
        return Err(format!(
            "failed to capture provisional stage identity at {}: {}",
            display_path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let metadata = unsafe { metadata.assume_init() };
    if metadata.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err(format!(
            "newly created stage is not regular at {}",
            display_path.display()
        ));
    }
    Ok(Identity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn inspect_open_object(
    file: &File,
    display_path: &Path,
) -> Result<(Identity, libc::mode_t, AccessState), String> {
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
    let extended_acl = capture_extended_acl(file.as_raw_fd(), display_path)?;
    Ok((
        Identity {
            device: metadata.st_dev,
            inode: metadata.st_ino,
        },
        metadata.st_mode & libc::S_IFMT,
        AccessState {
            mode: metadata.st_mode & 0o7777,
            owner: metadata.st_uid,
            group: metadata.st_gid,
            flags: metadata.st_flags,
            extended_acl,
        },
    ))
}

fn capture_extended_acl(fd: RawFd, display_path: &Path) -> Result<Vec<u8>, String> {
    let mut attributes = libc::attrlist {
        bitmapcount: libc::ATTR_BIT_MAP_COUNT,
        reserved: 0,
        commonattr: libc::ATTR_CMN_EXTENDED_SECURITY,
        volattr: 0,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut buffer = vec![0_u8; 64 * 1024];
    let result = unsafe {
        libc::fgetattrlist(
            fd,
            (&mut attributes as *mut libc::attrlist).cast::<libc::c_void>(),
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            0,
        )
    };
    if result == -1 {
        return Err(format!(
            "failed to capture extended ACL through the open descriptor for {}: {}",
            display_path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let length_size = std::mem::size_of::<u32>();
    let reference_size = std::mem::size_of::<libc::attrreference_t>();
    let returned_length = unsafe { buffer.as_ptr().cast::<u32>().read_unaligned() } as usize;
    if returned_length < length_size + reference_size || returned_length > buffer.len() {
        return Err(format!(
            "extended ACL descriptor response had an invalid length for {}: {returned_length}",
            display_path.display(),
        ));
    }
    let reference_pointer = unsafe { buffer.as_ptr().add(length_size) };
    let reference = unsafe {
        reference_pointer
            .cast::<libc::attrreference_t>()
            .read_unaligned()
    };
    let data_start = (length_size as i64)
        .checked_add(reference.attr_dataoffset as i64)
        .ok_or_else(|| {
            format!(
                "extended ACL descriptor response overflowed for {}",
                display_path.display()
            )
        })?;
    if data_start < 0 {
        return Err(format!(
            "extended ACL descriptor response had a negative data offset for {}",
            display_path.display()
        ));
    }
    let data_start = data_start as usize;
    let data_end = data_start
        .checked_add(reference.attr_length as usize)
        .ok_or_else(|| {
            format!(
                "extended ACL descriptor response overflowed for {}",
                display_path.display()
            )
        })?;
    if data_start < length_size + reference_size || data_end > returned_length {
        return Err(format!(
            "extended ACL descriptor response was out of bounds for {}",
            display_path.display()
        ));
    }
    Ok(buffer[data_start..data_end].to_vec())
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

fn quarantine_and_delete_sealed_slot(
    directory: &DirectoryLease,
    name: &CString,
    display_path: &Path,
    role: &str,
    seal: &FileSeal,
) -> Result<(), String> {
    // Atomically remove the pathname occupant from the live namespace first.
    // Only the quarantined object is compared with the held descriptor seal
    // (identity, exact bytes, and selected access policy) and then unlinked.
    directory.validate_exclusive_namespace()?;
    let quarantine_name = create_quarantine_name(name)?;
    let quarantine_path = slot_display_path(&directory.display_path, &quarantine_name);
    rename_slot(directory.fd(), name, &quarantine_name, RENAME_EXCL).map_err(|error| {
        format!(
            "failed to move {role} into a unique quarantine slot at {}: {error}; no file was deleted; recovery path remains: {}",
            display_path.display(),
            display_path.display(),
        )
    })?;
    #[cfg(test)]
    if MUTATE_QUARANTINE_AFTER_MOVE.with(|flag| flag.replace(false)) {
        fs::write(&quarantine_path, b"injected quarantine mutation").map_err(|error| {
            format!(
                "failed to inject quarantine mutation for test at {}: {error}",
                quarantine_path.display()
            )
        })?;
    }
    if let Err(error) = seal.validate_slot(
        directory.fd(),
        &quarantine_name,
        &quarantine_path,
        &format!("quarantined {role}"),
    ) {
        return Err(format!(
            "quarantined {role} did not match its held descriptor seal: {error}; no file was deleted; recovery path: {}",
            quarantine_path.display()
        ));
    }
    directory.validate_exclusive_namespace().map_err(|error| {
        format!(
            "exclusive namespace validation failed after quarantining {role}: {error}; no file was deleted; recovery path: {}",
            quarantine_path.display()
        )
    })?;
    unlink_slot(directory.fd(), &quarantine_name).map_err(|error| {
        format!(
            "failed to unlink validated quarantined {role}: {error}; recovery path: {}",
            quarantine_path.display()
        )
    })
}

fn slot_display_path(directory: &Path, name: &CString) -> PathBuf {
    directory.join(std::ffi::OsString::from_vec(name.as_bytes().to_vec()))
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
    let mut directories: Vec<(PathBuf, Arc<DirectoryLease>)> = Vec::new();
    for (source, destination) in pairs {
        if targets
            .iter()
            .any(|target: &Target| target.display_path == destination)
        {
            return Err(format!("duplicate destination: {}", destination.display()));
        }
        let parent = validate_destination(&repo_root, &destination)?;
        let directory = if let Some((_, directory)) =
            directories.iter().find(|(existing, _)| existing == &parent)
        {
            Arc::clone(directory)
        } else {
            let directory = Arc::new(DirectoryLease::acquire(&parent)?);
            directories.push((parent, Arc::clone(&directory)));
            directory
        };
        targets.push(Target::prepare_with_directory(
            &source,
            &destination,
            directory,
        )?);
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

    fn recovery_path(error: &str) -> PathBuf {
        PathBuf::from(
            error
                .rsplit_once("recovery path: ")
                .map(|(_, path)| path)
                .expect("error includes recovery path"),
        )
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
    fn finish_quarantines_replaced_backup_without_deleting_it() {
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
        assert!(!backup.exists());
        let recovery = recovery_path(&error);
        assert_eq!(fs::read(&recovery).expect("read interloper"), b"interloper");
        assert_eq!(
            fs::read(&parked_backup).expect("read parked backup"),
            b"old bytes"
        );
    }

    #[test]
    fn discard_quarantines_replaced_stage_without_deleting_it() {
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
        assert!(!stage.exists());
        let recovery = recovery_path(&error);
        assert_eq!(fs::read(&recovery).expect("read interloper"), b"interloper");
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

    #[test]
    fn early_stage_failure_is_cleanup_safe_from_creation() {
        let root = tempfile::tempdir().expect("create root");
        let (directory, mut target) = prepared_existing_target(root.path());
        FAIL_STAGE_AFTER_CREATE.with(|flag| flag.set(true));

        let error = target.stage().expect_err("inject early stage failure");
        assert!(error.contains("post-create pre-seal"), "{error}");
        let stage = stage_path(&directory, &target);
        assert!(stage.exists());

        target.discard_stage().expect("discard provisional stage");
        assert!(!stage.exists());
    }

    #[test]
    fn publish_run_cleans_a_post_create_pre_seal_failure() {
        let root = tempfile::tempdir().expect("create root");
        let directory = root.path().join("generated");
        fs::create_dir(&directory).expect("create directory");
        let source = root.path().join("source");
        let destination = directory.join("output");
        fs::write(&source, b"new bytes").expect("write source");
        FAIL_STAGE_AFTER_CREATE.with(|flag| flag.set(true));

        let error = run(&[
            "publish".to_owned(),
            root.path().display().to_string(),
            source.display().to_string(),
            destination.display().to_string(),
        ])
        .expect_err("inject run-level early stage failure");

        assert!(error.contains("post-create pre-seal"), "{error}");
        assert!(!destination.exists());
        let leftovers: Vec<_> = fs::read_dir(&directory)
            .expect("read destination directory")
            .collect::<Result<_, _>>()
            .expect("collect destination entries");
        assert!(leftovers.is_empty(), "unexpected leftovers: {leftovers:?}");
    }

    #[test]
    fn quarantine_content_mutation_is_retained_for_recovery() {
        let root = tempfile::tempdir().expect("create root");
        let (directory, mut target) = prepared_existing_target(root.path());
        target.stage().expect("stage target");
        let stage = stage_path(&directory, &target);
        MUTATE_QUARANTINE_AFTER_MOVE.with(|flag| flag.set(true));

        let error = target
            .discard_stage()
            .expect_err("reject mutated quarantine object");

        assert!(error.contains("content mismatched"), "{error}");
        assert!(!stage.exists());
        let recovery = recovery_path(&error);
        assert_eq!(
            fs::read(&recovery).expect("read retained quarantine"),
            b"injected quarantine mutation"
        );
    }

    #[test]
    fn source_symlink_is_rejected_without_materializing_a_second_read_path() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("create root");
        let real_source = root.path().join("real-source");
        let linked_source = root.path().join("linked-source");
        fs::write(&real_source, b"generated").expect("write source");
        symlink(&real_source, &linked_source).expect("link source");

        let error = read_sealed_source(&linked_source).expect_err("reject source symlink");
        assert!(error.contains("symlink"), "{error}");
    }

    #[test]
    fn source_replacement_after_open_does_not_change_descriptor_bytes() {
        let root = tempfile::tempdir().expect("create root");
        let source = root.path().join("source");
        let parked_source = root.path().join("parked-source");
        fs::write(&source, b"original source").expect("write source");
        let handle = open_source_no_follow(&source).expect("open source descriptor");
        fs::rename(&source, &parked_source).expect("park original source");
        fs::write(&source, b"replacement source").expect("replace source pathname");

        let seal = FileSeal::capture(handle, &source).expect("seal opened source");

        assert_eq!(seal.bytes, b"original source");
        assert_eq!(
            fs::read(&source).expect("read replacement"),
            b"replacement source"
        );
    }

    #[test]
    fn extended_acl_mutation_is_part_of_the_access_state_seal() {
        let root = tempfile::tempdir().expect("create root");
        let (directory, mut target) = prepared_existing_target(root.path());
        target.stage().expect("stage target");
        target.publish().expect("publish target");
        let backup = stage_path(&directory, &target);
        let status = std::process::Command::new("/bin/chmod")
            .arg("+a")
            .arg("everyone deny write")
            .arg(&backup)
            .status()
            .expect("run chmod ACL mutation");
        assert!(status.success(), "chmod ACL mutation failed: {status}");
        let acl = capture_extended_acl(
            File::open(&backup)
                .expect("open ACL-mutated backup")
                .as_raw_fd(),
            &backup,
        )
        .expect("capture mutated ACL");
        assert!(!acl.is_empty(), "mutated ACL must be captured");

        let error = target
            .rollback()
            .expect_err("reject changed rollback backup ACL");

        assert!(error.contains("access state mismatched"), "{error}");
        assert_eq!(
            fs::read(&backup).expect("read protected backup"),
            b"old bytes"
        );
    }
}
