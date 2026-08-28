#![forbid(unsafe_code)]

pub mod tui;

use std::ffi::{OsStr, OsString};
use std::fmt::Write as FmtWrite;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use diskplan_core::framing::{FrameError, read_frame, write_frame};
use diskplan_core::handshake::{AcceptedHandshakeError, rust_client_hello, validate_accepted};
use diskplan_proto::diskplan::v1::{
    BusinessEnvelope, EngineEvent, Envelope, HelloAccepted, ScanControlKind, ScanControlRequest,
    StartScanRequest, envelope,
};
use prost::Message;
use rustix::fs::{
    AtFlags, CWD, Mode, OFlags, RenameFlags, mkdirat, openat, renameat_with, statat, unlinkat,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);
const EXIT_OBSERVATION_GRACE: Duration = Duration::from_millis(50);
const HANDSHAKE_SEQUENCE: u64 = 1;
const FRAME_QUEUE_CAPACITY: usize = 1;
const MAX_ENGINE_BYTES: u64 = 512 * 1024 * 1024;

type FrameResult = Result<Option<Vec<u8>>, FrameError>;

#[derive(Clone, Debug, Eq, PartialEq)]
struct EngineObjectIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    link_count: u64,
    size: u64,
    flags: u32,
}

impl EngineObjectIdentity {
    fn from_file(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "engine is not a regular file",
            ));
        }
        let mode = metadata.mode();
        if mode & 0o022 != 0 || mode & 0o111 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "engine access policy is unsafe",
            ));
        }
        if metadata.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "engine must have exactly one filesystem link",
            ));
        }
        if metadata.size() > MAX_ENGINE_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                EngineDigestLengthIssue::Oversize {
                    limit: MAX_ENGINE_BYTES,
                },
            ));
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode,
            uid: metadata.uid(),
            gid: metadata.gid(),
            link_count: metadata.nlink(),
            size: metadata.size(),
            flags: selected_file_access_flags(file)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LaunchDirectoryIdentity {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    flags: u32,
    filesystem_id: u64,
    mount_flags: u64,
}

impl LaunchDirectoryIdentity {
    fn from_file(file: &File, launch_root: bool) -> io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.file_type().is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "engine launch ancestor is not a directory",
            ));
        }
        let identity = Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            flags: selected_file_access_flags(file)?,
            filesystem_id: rustix::fs::fstatvfs(file)?.f_fsid,
            mount_flags: selected_mount_access_flags(file)?,
        };
        identity.require_safe_access(launch_root)?;
        Ok(identity)
    }

    fn require_safe_access(&self, launch_root: bool) -> io::Result<()> {
        let current_uid = rustix::process::geteuid().as_raw();
        let current_gid = rustix::process::getegid().as_raw();
        let permissions = self.mode & 0o7777;
        let safe = if launch_root {
            self.uid == current_uid
                && self.gid == current_gid
                && permissions == 0o700
                && self.flags == 0
        } else {
            let owner_safe = self.uid == 0 || self.uid == current_uid;
            let writable_by_others = permissions & 0o022 != 0;
            let root_sticky = self.uid == 0 && permissions & 0o1000 != 0;
            owner_safe && (!writable_by_others || root_sticky) && self.flags == 0
        };
        if !safe {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "engine launch ancestor access policy is unsafe",
            ));
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn selected_file_access_flags(file: &File) -> io::Result<u32> {
    let metadata = rustix::fs::fstat(file)?;
    // Darwin's security-relevant subset from <sys/stat.h>. UF_HIDDEN and
    // UF_NODUMP are deliberately excluded because they do not change access.
    let mask: u32 = 0x0000_0002
        | 0x0000_0004
        | 0x0000_0080
        | 0x0002_0000
        | 0x0004_0000
        | 0x0008_0000
        | 0x0010_0000;
    Ok(metadata.st_flags & mask)
}

#[cfg(not(target_os = "macos"))]
fn selected_file_access_flags(_file: &File) -> io::Result<u32> {
    Ok(0)
}

#[cfg(target_os = "macos")]
fn selected_mount_access_flags(file: &File) -> io::Result<u64> {
    let metadata = rustix::fs::fstatfs(file)?;
    let mask = (libc::MNT_RDONLY | libc::MNT_NOEXEC | libc::MNT_NOSUID | libc::MNT_NODEV) as u64;
    Ok((metadata.f_flags as u64) & mask)
}

#[cfg(not(target_os = "macos"))]
fn selected_mount_access_flags(_file: &File) -> io::Result<u64> {
    Ok(0)
}

#[derive(Debug)]
struct LaunchDirectoryBinding {
    file: File,
    name: Option<OsString>,
    identity: LaunchDirectoryIdentity,
    parent_device: u64,
    parent_filesystem_id: u64,
    crosses_device: bool,
    crosses_mount: bool,
}

#[derive(Debug, Error)]
enum LaunchCleanupError {
    #[error("launch namespace revalidation failed; retained unverified path hint {path}: {source}")]
    NamespaceChanged {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("descriptor-bound engine snapshot cleanup is incomplete at {path}: {source}")]
    SnapshotRemoval {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("descriptor-bound engine launch-directory cleanup is incomplete at {path}: {source}")]
    DirectoryRemoval {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

#[derive(Debug)]
struct LaunchDirectoryGuard {
    directories: Option<Vec<LaunchDirectoryBinding>>,
    path: PathBuf,
}

impl LaunchDirectoryGuard {
    fn into_parts(mut self) -> (Vec<LaunchDirectoryBinding>, PathBuf) {
        let directories = self
            .directories
            .take()
            .expect("launch directory guard is armed");
        (directories, self.path.clone())
    }
}

impl Drop for LaunchDirectoryGuard {
    fn drop(&mut self) {
        let Some(directories) = self.directories.as_ref() else {
            return;
        };
        if let Err(error) = cleanup_bound_launch_directory(directories, &self.path) {
            eprintln!("diskplan: {error}");
        }
    }
}

#[derive(Debug)]
struct LaunchNamespace {
    directories: Vec<LaunchDirectoryBinding>,
    path: PathBuf,
    engine_name: OsString,
    engine_file: File,
    engine_identity: EngineObjectIdentity,
    engine_sha256: [u8; 32],
}

impl LaunchNamespace {
    fn create(
        source: &File,
        source_identity: &EngineObjectIdentity,
        source_sha256: [u8; 32],
    ) -> io::Result<Self> {
        let temporary_parent = std::fs::canonicalize(std::env::temp_dir())?;
        let launch_guard = create_launch_directory(&temporary_parent)?;
        let launch_directory = &launch_guard
            .directories
            .as_ref()
            .expect("launch directory guard is armed")
            .last()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "launch chain is empty"))?
            .file;
        let engine_name = OsString::from("diskplan-engine");
        let engine_fd = openat(
            launch_directory,
            &engine_name,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK,
            Mode::from_raw_mode(0o700),
        )?;
        let mut writable_engine_file = File::from(engine_fd);
        copy_exact_file(source, &mut writable_engine_file, source_identity.size)?;
        writable_engine_file.flush()?;
        rustix::fs::fchown(
            &writable_engine_file,
            Some(rustix::process::geteuid()),
            Some(rustix::process::getegid()),
        )?;
        writable_engine_file.set_permissions(std::fs::Permissions::from_mode(0o500))?;
        writable_engine_file.sync_all()?;
        drop(writable_engine_file);
        let engine_file = File::from(openat(
            launch_directory,
            &engine_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?);
        let engine_identity = EngineObjectIdentity::from_file(&engine_file)?;
        let engine_sha256 = digest_file(&engine_file, engine_identity.size)?;
        if engine_sha256 != source_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private engine launch snapshot does not match bound source content",
            ));
        }
        let (directories, path) = launch_guard.into_parts();
        let result = Self {
            directories,
            path,
            engine_name,
            engine_file,
            engine_identity,
            engine_sha256,
        };
        result.revalidate()?;
        Ok(result)
    }

    fn revalidate_directory_count(&self, count: usize) -> io::Result<()> {
        revalidate_directory_bindings(&self.directories, count)
    }

    fn revalidate_directories(&self) -> io::Result<()> {
        self.revalidate_directory_count(self.directories.len())
    }

    fn revalidate(&self) -> io::Result<()> {
        self.revalidate_directories()?;
        if EngineObjectIdentity::from_file(&self.engine_file)? != self.engine_identity
            || digest_file(&self.engine_file, self.engine_identity.size)? != self.engine_sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private engine launch snapshot changed",
            ));
        }
        let launch_directory = &self
            .directories
            .last()
            .expect("launch chain is non-empty")
            .file;
        let launch_slot = File::from(openat(
            launch_directory,
            &self.engine_name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )?);
        if EngineObjectIdentity::from_file(&launch_slot)? != self.engine_identity
            || digest_file(&launch_slot, self.engine_identity.size)? != self.engine_sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "private engine launch slot no longer selects the bound snapshot",
            ));
        }
        Ok(())
    }

    fn cleanup_exact(&mut self) -> Result<(), LaunchCleanupError> {
        self.revalidate()
            .map_err(|source| LaunchCleanupError::NamespaceChanged {
                path: self.path.clone(),
                source,
            })?;
        cleanup_bound_engine_snapshot(
            &self.directories,
            &self.path,
            &self.engine_name,
            &self.engine_identity,
            self.engine_sha256,
        )?;
        cleanup_bound_launch_directory(&self.directories, &self.path)
    }
}

impl Drop for LaunchNamespace {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup_exact() {
            eprintln!("diskplan: {error}");
        }
    }
}

fn directory_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK
}

fn revalidate_directory_bindings(
    directories: &[LaunchDirectoryBinding],
    count: usize,
) -> io::Result<()> {
    for (index, binding) in directories.iter().take(count).enumerate() {
        let launch_root = index + 1 == directories.len();
        if LaunchDirectoryIdentity::from_file(&binding.file, launch_root)? != binding.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "engine launch ancestor identity, access policy, or mount flags changed",
            ));
        }
        let reopened = if index == 0 {
            File::from(openat(CWD, "/", directory_open_flags(), Mode::empty())?)
        } else {
            let parent = &directories[index - 1];
            File::from(openat(
                &parent.file,
                binding.name.as_ref().expect("non-root binding has a name"),
                directory_open_flags(),
                Mode::empty(),
            )?)
        };
        if LaunchDirectoryIdentity::from_file(&reopened, launch_root)? != binding.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "engine launch ancestor pathname no longer selects the bound directory",
            ));
        }
        let parent_device = if index == 0 {
            binding.identity.device
        } else {
            directories[index - 1].identity.device
        };
        let parent_filesystem_id = if index == 0 {
            binding.identity.filesystem_id
        } else {
            directories[index - 1].identity.filesystem_id
        };
        if binding.parent_device != parent_device
            || binding.crosses_device != (binding.identity.device != parent_device)
            || binding.parent_filesystem_id != parent_filesystem_id
            || binding.crosses_mount != (binding.identity.filesystem_id != parent_filesystem_id)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "engine launch ancestor mount boundary changed",
            ));
        }
    }
    Ok(())
}

fn restore_quarantined_slot(parent: &File, quarantine: &OsStr, original: &OsStr) -> io::Result<()> {
    renameat_with(parent, quarantine, parent, original, RenameFlags::NOREPLACE)
        .map_err(io::Error::from)
}

fn cleanup_bound_engine_snapshot(
    directories: &[LaunchDirectoryBinding],
    path: &Path,
    engine_name: &OsStr,
    expected_identity: &EngineObjectIdentity,
    expected_sha256: [u8; 32],
) -> Result<(), LaunchCleanupError> {
    let launch_directory = &directories.last().expect("launch chain is non-empty").file;
    let quarantine = random_scoped_name(".diskplan-engine-cleanup.").map_err(|source| {
        LaunchCleanupError::SnapshotRemoval {
            path: path.to_path_buf(),
            source,
        }
    })?;
    renameat_with(
        launch_directory,
        engine_name,
        launch_directory,
        &quarantine,
        RenameFlags::NOREPLACE,
    )
    .map_err(|source| LaunchCleanupError::SnapshotRemoval {
        path: path.to_path_buf(),
        source: io::Error::from(source),
    })?;
    let quarantined = match openat(
        launch_directory,
        &quarantine,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(source) => {
            let restore = restore_quarantined_slot(launch_directory, &quarantine, engine_name);
            return Err(LaunchCleanupError::SnapshotRemoval {
                path: path.to_path_buf(),
                source: io::Error::other(format!(
                    "cannot reopen quarantined snapshot: {}; restore result: {}",
                    io::Error::from(source),
                    restore
                        .map(|()| "restored".to_string())
                        .unwrap_or_else(|error| error.to_string())
                )),
            });
        }
    };
    let matches = match EngineObjectIdentity::from_file(&quarantined).and_then(|identity| {
        Ok(identity == *expected_identity
            && digest_file(&quarantined, expected_identity.size)? == expected_sha256)
    }) {
        Ok(matches) => matches,
        Err(proof_error) => {
            let restore = restore_quarantined_slot(launch_directory, &quarantine, engine_name);
            return Err(LaunchCleanupError::SnapshotRemoval {
                path: path.to_path_buf(),
                source: io::Error::other(format!(
                    "cannot revalidate quarantined snapshot: {proof_error}; restore result: {}",
                    restore
                        .map(|()| "restored".to_string())
                        .unwrap_or_else(|error| error.to_string())
                )),
            });
        }
    };
    if !matches {
        let restore = restore_quarantined_slot(launch_directory, &quarantine, engine_name);
        return Err(LaunchCleanupError::NamespaceChanged {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "quarantined snapshot proof mismatch; restore result: {}",
                    restore
                        .map(|()| "restored".to_string())
                        .unwrap_or_else(|error| error.to_string())
                ),
            ),
        });
    }
    if let Err(source) = unlinkat(launch_directory, &quarantine, AtFlags::empty()) {
        let restore = restore_quarantined_slot(launch_directory, &quarantine, engine_name);
        return Err(LaunchCleanupError::SnapshotRemoval {
            path: path.to_path_buf(),
            source: io::Error::other(format!(
                "cannot remove exact quarantined snapshot: {}; restore result: {}",
                io::Error::from(source),
                restore
                    .map(|()| "restored".to_string())
                    .unwrap_or_else(|error| error.to_string())
            )),
        });
    }
    launch_directory
        .sync_all()
        .map_err(|source| LaunchCleanupError::SnapshotRemoval {
            path: path.to_path_buf(),
            source,
        })?;
    for name in [engine_name, quarantine.as_os_str()] {
        match statat(launch_directory, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Err(source) => {
                return Err(LaunchCleanupError::SnapshotRemoval {
                    path: path.to_path_buf(),
                    source: io::Error::from(source),
                });
            }
            Ok(_) => {
                return Err(LaunchCleanupError::SnapshotRemoval {
                    path: path.to_path_buf(),
                    source: io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "engine snapshot slot was repopulated during exact cleanup",
                    ),
                });
            }
        }
    }
    Ok(())
}

fn cleanup_bound_launch_directory(
    directories: &[LaunchDirectoryBinding],
    path: &Path,
) -> Result<(), LaunchCleanupError> {
    revalidate_directory_bindings(directories, directories.len()).map_err(|source| {
        LaunchCleanupError::NamespaceChanged {
            path: path.to_path_buf(),
            source,
        }
    })?;
    let leaf = directories.last().expect("launch chain is non-empty");
    let parent = directories
        .get(directories.len().saturating_sub(2))
        .expect("launch root has a parent");
    let leaf_name = leaf.name.as_ref().expect("launch root has a slot name");
    let quarantine = random_scoped_name(".diskplan-launch-cleanup.").map_err(|source| {
        LaunchCleanupError::DirectoryRemoval {
            path: path.to_path_buf(),
            source,
        }
    })?;
    renameat_with(
        &parent.file,
        leaf_name,
        &parent.file,
        &quarantine,
        RenameFlags::NOREPLACE,
    )
    .map_err(|source| LaunchCleanupError::DirectoryRemoval {
        path: path.to_path_buf(),
        source: io::Error::from(source),
    })?;
    let quarantined = match openat(
        &parent.file,
        &quarantine,
        directory_open_flags(),
        Mode::empty(),
    ) {
        Ok(file) => File::from(file),
        Err(source) => {
            let restore = restore_quarantined_slot(&parent.file, &quarantine, leaf_name);
            return Err(LaunchCleanupError::DirectoryRemoval {
                path: path.to_path_buf(),
                source: io::Error::other(format!(
                    "cannot reopen quarantined launch directory: {}; restore result: {}",
                    io::Error::from(source),
                    restore
                        .map(|()| "restored".to_string())
                        .unwrap_or_else(|error| error.to_string())
                )),
            });
        }
    };
    let quarantine_identity = match LaunchDirectoryIdentity::from_file(&quarantined, true) {
        Ok(identity) => identity,
        Err(proof_error) => {
            let restore = restore_quarantined_slot(&parent.file, &quarantine, leaf_name);
            return Err(LaunchCleanupError::DirectoryRemoval {
                path: path.to_path_buf(),
                source: io::Error::other(format!(
                    "cannot revalidate quarantined launch directory: {proof_error}; restore result: {}",
                    restore
                        .map(|()| "restored".to_string())
                        .unwrap_or_else(|error| error.to_string())
                )),
            });
        }
    };
    if quarantine_identity != leaf.identity {
        let restore = restore_quarantined_slot(&parent.file, &quarantine, leaf_name);
        return Err(LaunchCleanupError::NamespaceChanged {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "quarantined launch directory proof mismatch; restore result: {}",
                    restore
                        .map(|()| "restored".to_string())
                        .unwrap_or_else(|error| error.to_string())
                ),
            ),
        });
    }
    if let Err(source) = unlinkat(&parent.file, &quarantine, AtFlags::REMOVEDIR) {
        let restore = restore_quarantined_slot(&parent.file, &quarantine, leaf_name);
        return Err(LaunchCleanupError::DirectoryRemoval {
            path: path.to_path_buf(),
            source: io::Error::other(format!(
                "cannot remove exact quarantined launch directory: {}; restore result: {}",
                io::Error::from(source),
                restore
                    .map(|()| "restored".to_string())
                    .unwrap_or_else(|error| error.to_string())
            )),
        });
    }
    parent
        .file
        .sync_all()
        .map_err(|source| LaunchCleanupError::DirectoryRemoval {
            path: path.to_path_buf(),
            source,
        })?;
    for name in [leaf_name.as_os_str(), quarantine.as_os_str()] {
        match statat(&parent.file, name, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {}
            Err(source) => {
                return Err(LaunchCleanupError::DirectoryRemoval {
                    path: path.to_path_buf(),
                    source: io::Error::from(source),
                });
            }
            Ok(_) => {
                return Err(LaunchCleanupError::DirectoryRemoval {
                    path: path.to_path_buf(),
                    source: io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "launch directory slot was repopulated during exact cleanup",
                    ),
                });
            }
        }
    }
    revalidate_directory_bindings(directories, directories.len() - 1).map_err(|source| {
        LaunchCleanupError::NamespaceChanged {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

fn random_scoped_name(prefix: &str) -> io::Result<OsString> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(io::Error::other)?;
    let mut name = String::from(prefix);
    for byte in random {
        write!(&mut name, "{byte:02x}").expect("writing to String cannot fail");
    }
    Ok(OsString::from(name))
}

fn create_launch_directory(temporary_parent: &Path) -> io::Result<LaunchDirectoryGuard> {
    let mut bindings = bind_launch_directory_chain(temporary_parent, false)?;
    let parent = bindings
        .last()
        .expect("absolute temporary parent has a root binding");
    let mut selected_name = None;
    for _ in 0..64 {
        let name = random_scoped_name("diskplan-engine-launch.")?;
        match mkdirat(&parent.file, &name, Mode::from_raw_mode(0o700)) {
            Ok(()) => {
                selected_name = Some(name);
                break;
            }
            Err(rustix::io::Errno::EXIST) => continue,
            Err(source) => return Err(io::Error::from(source)),
        }
    }
    let name = selected_name.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AlreadyExists,
            "cannot allocate a unique engine launch directory slot",
        )
    })?;
    let child = File::from(openat(
        &parent.file,
        &name,
        directory_open_flags(),
        Mode::empty(),
    )?);
    rustix::fs::fchown(
        &child,
        Some(rustix::process::geteuid()),
        Some(rustix::process::getegid()),
    )?;
    child.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    let identity = LaunchDirectoryIdentity::from_file(&child, true)?;
    let reopened = File::from(openat(
        &parent.file,
        &name,
        directory_open_flags(),
        Mode::empty(),
    )?);
    if LaunchDirectoryIdentity::from_file(&reopened, true)? != identity {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "engine launch directory slot changed while binding",
        ));
    }
    let path = temporary_parent.join(&name);
    let parent_device = parent.identity.device;
    let parent_filesystem_id = parent.identity.filesystem_id;
    bindings.push(LaunchDirectoryBinding {
        file: child,
        name: Some(name),
        parent_device,
        parent_filesystem_id,
        crosses_device: identity.device != parent_device,
        crosses_mount: identity.filesystem_id != parent_filesystem_id,
        identity,
    });
    Ok(LaunchDirectoryGuard {
        directories: Some(bindings),
        path,
    })
}

fn bind_launch_directory_chain(
    path: &Path,
    exact_leaf: bool,
) -> io::Result<Vec<LaunchDirectoryBinding>> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "engine launch directory is not absolute",
        ));
    }
    let root = File::from(openat(CWD, "/", directory_open_flags(), Mode::empty())?);
    let root_identity = LaunchDirectoryIdentity::from_file(&root, false)?;
    let mut bindings = vec![LaunchDirectoryBinding {
        file: root,
        name: None,
        identity: root_identity.clone(),
        parent_device: root_identity.device,
        parent_filesystem_id: root_identity.filesystem_id,
        crosses_device: false,
        crosses_mount: false,
    }];
    let component_count = path
        .components()
        .filter(|part| matches!(part, Component::Normal(_)))
        .count();
    for component in path.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let parent = bindings.last().expect("root binding exists");
        let child = File::from(openat(
            &parent.file,
            name,
            directory_open_flags(),
            Mode::empty(),
        )?);
        let parent_device = parent.identity.device;
        let parent_filesystem_id = parent.identity.filesystem_id;
        let launch_root = exact_leaf && bindings.len() == component_count;
        let identity = LaunchDirectoryIdentity::from_file(&child, launch_root)?;
        bindings.push(LaunchDirectoryBinding {
            file: child,
            name: Some(name.to_os_string()),
            parent_device,
            parent_filesystem_id,
            crosses_device: identity.device != parent_device,
            crosses_mount: identity.filesystem_id != parent_filesystem_id,
            identity,
        });
    }
    Ok(bindings)
}

#[derive(Clone, Debug)]
pub struct BoundEngine {
    source_file: Arc<File>,
    source_identity: EngineObjectIdentity,
    source_sha256: [u8; 32],
    launch: Arc<LaunchNamespace>,
}

impl BoundEngine {
    pub fn open(path: &Path) -> io::Result<Self> {
        // Protected properties: the descriptor fixes object identity, exact Unix
        // metadata fixes the launch access policy, and SHA-256 fixes content.
        // The pathname is never used again after this no-follow open.
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        let source_identity = EngineObjectIdentity::from_file(&file)?;
        let source_sha256 = digest_file(&file, source_identity.size)?;
        if EngineObjectIdentity::from_file(&file)? != source_identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "engine identity or access policy changed while binding content",
            ));
        }
        let launch = Arc::new(LaunchNamespace::create(
            &file,
            &source_identity,
            source_sha256,
        )?);
        if EngineObjectIdentity::from_file(&file)? != source_identity
            || digest_file(&file, source_identity.size)? != source_sha256
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "engine changed while creating its private launch snapshot",
            ));
        }
        Ok(Self {
            source_file: Arc::new(file),
            source_identity,
            source_sha256,
            launch,
        })
    }

    fn spawn_child(&self, configure: impl FnOnce(&mut Command)) -> io::Result<Child> {
        self.spawn_child_at_boundary(configure, || Ok(()))
    }

    fn spawn_child_at_boundary(
        &self,
        configure: impl FnOnce(&mut Command),
        before_spawn: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<Child> {
        self.revalidate()?;
        // macOS rejects native Mach-O execution through /dev/fd. Keep the
        // pathname launch inside BoundEngine so it cannot outlive the complete
        // owner-private namespace proof, and revalidate immediately on both
        // sides of the only operational pathname spawn.
        let mut command = Command::new(self.launch.path.join(&self.launch.engine_name));
        configure(&mut command);
        before_spawn()?;
        self.revalidate()?;
        let mut child = command.spawn()?;
        if let Err(error) = self.revalidate() {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
        Ok(child)
    }

    pub fn output(&self, arguments: &[&OsStr]) -> io::Result<Output> {
        let child = self.spawn_child(|command| {
            command
                .args(arguments)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        })?;
        let output = child.wait_with_output()?;
        self.revalidate()?;
        Ok(output)
    }

    pub fn revalidate(&self) -> io::Result<()> {
        let current = EngineObjectIdentity::from_file(&self.source_file)?;
        if current != self.source_identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bound engine identity or access policy changed",
            ));
        }
        if digest_file(&self.source_file, self.source_identity.size)? != self.source_sha256 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "bound engine content changed",
            ));
        }
        self.launch.revalidate()
    }
}

fn copy_exact_file(source: &File, destination: &mut File, expected_size: u64) -> io::Result<()> {
    let mut reader = source.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let copied = io::copy(
        &mut reader.take(expected_size.saturating_add(1)),
        destination,
    )?;
    if copied != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "engine size changed while creating its private launch snapshot",
        ));
    }
    Ok(())
}

#[derive(Debug, Error)]
enum EngineDigestLengthIssue {
    #[error("engine exceeds the executable size limit of {limit} bytes")]
    Oversize { limit: u64 },
    #[error("engine size changed while hashing: expected {expected} bytes, observed {actual}")]
    Mismatch { expected: u64, actual: u64 },
}

fn digest_file(file: &File, expected_size: u64) -> io::Result<[u8; 32]> {
    if expected_size > MAX_ENGINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            EngineDigestLengthIssue::Oversize {
                limit: MAX_ENGINE_BYTES,
            },
        ));
    }
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let read_limit = expected_size
        .saturating_add(1)
        .min(MAX_ENGINE_BYTES.saturating_add(1));
    let mut reader = reader.take(read_limit);
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut consumed = 0_u64;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        consumed += count as u64;
        digest.update(&buffer[..count]);
    }
    if consumed > MAX_ENGINE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::FileTooLarge,
            EngineDigestLengthIssue::Oversize {
                limit: MAX_ENGINE_BYTES,
            },
        ));
    }
    if consumed != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            EngineDigestLengthIssue::Mismatch {
                expected: expected_size,
                actual: consumed,
            },
        ));
    }
    Ok(digest.finalize().into())
}

#[cfg(test)]
mod bound_engine_tests {
    use super::*;
    use std::fs;

    fn bound_test_engine() -> (tempfile::TempDir, BoundEngine) {
        let root = tempfile::tempdir().expect("temporary source root");
        let path = root.path().join("diskplan-engine");
        fs::copy(
            std::env::current_exe().expect("current test executable"),
            &path,
        )
        .expect("copy test engine");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("set test engine mode");
        let engine = BoundEngine::open(&path).expect("bind test engine");
        (root, engine)
    }

    #[test]
    fn digest_length_failures_distinguish_oversize_from_mismatch() {
        let root = tempfile::tempdir().expect("temporary digest root");
        let path = root.path().join("engine");
        fs::write(&path, b"four").expect("write digest fixture");
        let file = File::open(path).expect("open digest fixture");

        let mismatch = digest_file(&file, 3).expect_err("unexpected length must fail");
        assert_eq!(mismatch.kind(), io::ErrorKind::InvalidData);
        assert!(matches!(
            mismatch
                .get_ref()
                .and_then(|error| error.downcast_ref::<EngineDigestLengthIssue>()),
            Some(EngineDigestLengthIssue::Mismatch { .. })
        ));

        let oversize = digest_file(&file, MAX_ENGINE_BYTES + 1)
            .expect_err("declared oversize executable must fail");
        assert_eq!(oversize.kind(), io::ErrorKind::FileTooLarge);
        assert!(matches!(
            oversize
                .get_ref()
                .and_then(|error| error.downcast_ref::<EngineDigestLengthIssue>()),
            Some(EngineDigestLengthIssue::Oversize { .. })
        ));
    }

    #[test]
    fn bound_engine_drop_removes_only_the_exact_launch_objects() {
        let (_source, engine) = bound_test_engine();
        let launch_path = engine.launch.path.clone();
        assert!(launch_path.join("diskplan-engine").is_file());
        drop(engine);
        assert!(!launch_path.exists());
    }

    #[test]
    fn bound_engine_drop_retains_replaced_launch_slot() {
        let (_source, engine) = bound_test_engine();
        let launch_path = engine.launch.path.clone();
        let retained = launch_path.with_extension("retained-test-object");
        fs::rename(&launch_path, &retained).expect("retire bound launch root");
        fs::create_dir(&launch_path).expect("create replacement launch root");
        fs::set_permissions(&launch_path, fs::Permissions::from_mode(0o700))
            .expect("set replacement launch mode");

        drop(engine);

        assert!(retained.join("diskplan-engine").is_file());
        assert!(launch_path.is_dir());
        fs::remove_dir_all(&retained).expect("remove retained test object");
        fs::remove_dir(&launch_path).expect("remove replacement test object");
    }

    #[test]
    fn bound_engine_drop_retains_replaced_snapshot_slot() {
        let (_source, engine) = bound_test_engine();
        let launch_path = engine.launch.path.clone();
        let snapshot = launch_path.join("diskplan-engine");
        let retained = launch_path.join("diskplan-engine.retained-test-object");
        fs::rename(&snapshot, &retained).expect("retire bound snapshot");
        fs::write(&snapshot, b"replacement snapshot").expect("write replacement snapshot");
        fs::set_permissions(&snapshot, fs::Permissions::from_mode(0o500))
            .expect("set replacement snapshot mode");

        drop(engine);

        assert!(retained.is_file());
        assert!(snapshot.is_file());
        fs::remove_dir_all(&launch_path).expect("remove retained snapshot test directory");
    }

    #[test]
    fn spawn_boundary_rejects_launch_ancestor_replacement() {
        let (_source, engine) = bound_test_engine();
        let launch_path = engine.launch.path.clone();
        let retained = launch_path.with_extension("spawn-retained-test-object");
        let error = engine
            .spawn_child_at_boundary(
                |command| {
                    command.arg("--help");
                },
                || {
                    fs::rename(&launch_path, &retained)?;
                    fs::create_dir(&launch_path)?;
                    fs::set_permissions(&launch_path, fs::Permissions::from_mode(0o700))?;
                    Ok(())
                },
            )
            .expect_err("replacement before spawn must fail closed");
        assert!(matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::NotFound
        ));
        drop(engine);
        fs::remove_dir_all(&retained).expect("remove retained spawn test object");
        fs::remove_dir(&launch_path).expect("remove replacement spawn test object");
    }
}

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("framing error: {0}")]
    Frame(#[from] FrameError),
    #[error("protobuf decode error: {0}")]
    Protobuf(#[from] prost::DecodeError),
    #[error("engine closed stdout before sending a complete response")]
    CleanEof,
    #[error("timed out waiting for engine {phase} after {timeout:?}")]
    Timeout {
        phase: &'static str,
        timeout: Duration,
    },
    #[error("engine sent an unexpected response during {phase}")]
    UnexpectedResponse { phase: &'static str },
    #[error("request_id must be non-zero")]
    InvalidRequestId,
    #[error("engine response sequence {actual} does not match request sequence {expected}")]
    ResponseSequenceMismatch { expected: u64, actual: u64 },
    #[error("engine event sequence {actual} does not immediately follow {previous}")]
    EventSequenceMismatch { previous: u64, actual: u64 },
    #[error("engine event sequence space is exhausted after {previous}")]
    EventSequenceExhausted { previous: u64 },
    #[error("engine event envelope sequence {envelope} does not match event sequence {event}")]
    EventEnvelopeSequenceMismatch { envelope: u64, event: u64 },
    #[error("engine rejected the request with code {code}: {detail}")]
    Rejected { code: i32, detail: String },
    #[error("engine handshake acceptance is invalid: {0}")]
    InvalidAcceptance(#[from] AcceptedHandshakeError),
    #[error("engine exited with status {code:?}")]
    EngineFailure { code: Option<i32> },
    #[error("engine exited after handshake instead of entering the ready state")]
    EngineExitedAfterHandshake,
    #[error("engine did not negotiate the required scan-control-v1 capability")]
    MissingScanControlCapability,
    #[error("engine emitted an extra framed message while shutting down")]
    ExtraFrameAfterShutdown,
    #[error("engine stdout decoder disconnected without reporting clean EOF")]
    DecoderDisconnected,
    #[error(
        "engine cleanup is incomplete: child {child_process_id} in process group \
         {process_group_id} did not exit after SIGKILL within {timeout:?}; reaping continues in \
         the background"
    )]
    CleanupIncomplete {
        child_process_id: u32,
        process_group_id: u32,
        timeout: Duration,
    },
    #[error(
        "engine cleanup is incomplete: process group {process_group_id} still exists after \
         SIGKILL and {timeout:?}"
    )]
    ProcessGroupCleanupIncomplete {
        process_group_id: u32,
        timeout: Duration,
    },
}

pub struct EngineSession {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    frames: Receiver<FrameResult>,
    response_timeout: Duration,
    accepted: HelloAccepted,
    last_event_sequence: u64,
    process_group_id: u32,
    reaper: SyncSender<Child>,
}

impl EngineSession {
    pub fn connect(engine: &Path) -> Result<Self, ClientError> {
        Self::connect_with_timeout(engine, DEFAULT_HANDSHAKE_TIMEOUT)
    }

    pub fn connect_with_timeout(engine: &Path, timeout: Duration) -> Result<Self, ClientError> {
        let mut command = Command::new(engine);
        Self::spawn_command(&mut command, timeout)
    }

    pub fn connect_bound(engine: &BoundEngine) -> Result<Self, ClientError> {
        Self::connect_bound_with_timeout(engine, DEFAULT_HANDSHAKE_TIMEOUT)
    }

    pub fn connect_bound_with_timeout(
        engine: &BoundEngine,
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let child = engine.spawn_child(|command| {
            command
                .process_group(0)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit());
        })?;
        Self::connect_spawned(child, timeout)
    }

    pub fn spawn_command(command: &mut Command, timeout: Duration) -> Result<Self, ClientError> {
        command.process_group(0);
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        Self::connect_spawned(child, timeout)
    }

    fn connect_spawned(mut child: Child, timeout: Duration) -> Result<Self, ClientError> {
        let reaper = spawn_reaper()?;
        let stdin = child
            .stdin
            .take()
            .expect("Stdio::piped must create an engine stdin handle");
        let mut stdout = child
            .stdout
            .take()
            .expect("Stdio::piped must create an engine stdout handle");
        let (sender, frames) = mpsc::sync_channel(FRAME_QUEUE_CAPACITY);
        let process_group_id = child.id();
        thread::spawn(move || {
            loop {
                let result = read_frame(&mut stdout);
                let terminal = !matches!(result, Ok(Some(_)));
                if sender.send(result).is_err() || terminal {
                    break;
                }
            }
        });

        let mut session = Self {
            child: Some(child),
            stdin: Some(stdin),
            frames,
            response_timeout: timeout,
            accepted: HelloAccepted::default(),
            last_event_sequence: 0,
            process_group_id,
            reaper,
        };
        session.perform_handshake()?;
        Ok(session)
    }

    pub fn accepted(&self) -> &HelloAccepted {
        &self.accepted
    }

    pub fn request_business(
        &mut self,
        sequence: u64,
        message_type: impl Into<String>,
        payload: Vec<u8>,
    ) -> Result<Envelope, ClientError> {
        let request = Envelope {
            sequence,
            body: Some(envelope::Body::Business(BusinessEnvelope {
                r#type: message_type.into(),
                payload,
            })),
        };
        self.write_envelope(&request)?;
        let response = self.read_envelope("business response")?;
        if response.sequence != sequence {
            return Err(ClientError::ResponseSequenceMismatch {
                expected: sequence,
                actual: response.sequence,
            });
        }
        Ok(response)
    }

    pub fn send_start_scan(
        &mut self,
        request_id: u64,
        profile: impl Into<String>,
    ) -> Result<(), ClientError> {
        if request_id == 0 {
            return Err(ClientError::InvalidRequestId);
        }
        self.write_envelope(&Envelope {
            sequence: request_id,
            body: Some(envelope::Body::StartScanRequest(StartScanRequest {
                request_id,
                profile: profile.into(),
            })),
        })
    }

    pub fn send_scan_control(
        &mut self,
        request_id: u64,
        control: ScanControlKind,
    ) -> Result<(), ClientError> {
        if request_id == 0 {
            return Err(ClientError::InvalidRequestId);
        }
        self.write_envelope(&Envelope {
            sequence: request_id,
            body: Some(envelope::Body::ScanControlRequest(ScanControlRequest {
                request_id,
                control: control as i32,
            })),
        })
    }

    pub fn read_engine_event(&mut self) -> Result<EngineEvent, ClientError> {
        self.read_engine_event_with_timeout(self.response_timeout)
    }

    pub fn read_engine_event_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<EngineEvent, ClientError> {
        let envelope = self.read_envelope_with_timeout("engine event", timeout)?;
        let Some(envelope::Body::EngineEvent(event)) = envelope.body else {
            return Err(ClientError::UnexpectedResponse {
                phase: "engine event",
            });
        };
        if envelope.sequence != event.event_sequence {
            return Err(ClientError::EventEnvelopeSequenceMismatch {
                envelope: envelope.sequence,
                event: event.event_sequence,
            });
        }
        let expected =
            self.last_event_sequence
                .checked_add(1)
                .ok_or(ClientError::EventSequenceExhausted {
                    previous: self.last_event_sequence,
                })?;
        if event.event_sequence != expected {
            return Err(ClientError::EventSequenceMismatch {
                previous: self.last_event_sequence,
                actual: event.event_sequence,
            });
        }
        self.last_event_sequence = event.event_sequence;
        Ok(event)
    }

    pub fn shutdown(mut self) -> Result<(), ClientError> {
        self.stdin.take();
        let status = self.wait_or_terminate();
        let drain = self.drain_stdout();
        let status = status?;
        drain?;
        match status {
            status if status.success() => Ok(()),
            status => Err(ClientError::EngineFailure {
                code: status.code(),
            }),
        }
    }

    fn perform_handshake(&mut self) -> Result<(), ClientError> {
        let hello = rust_client_hello();
        let request = Envelope {
            sequence: HANDSHAKE_SEQUENCE,
            body: Some(envelope::Body::Hello(hello.clone())),
        };
        self.write_envelope(&request)?;
        let response = self.read_envelope("handshake response")?;
        if response.sequence != HANDSHAKE_SEQUENCE {
            return Err(ClientError::ResponseSequenceMismatch {
                expected: HANDSHAKE_SEQUENCE,
                actual: response.sequence,
            });
        }
        match response.body {
            Some(envelope::Body::HelloAccepted(accepted)) => {
                validate_accepted(&hello, HANDSHAKE_SEQUENCE, response.sequence, &accepted)?;
                if self.child_mut()?.try_wait()?.is_some() {
                    return Err(ClientError::EngineExitedAfterHandshake);
                }
                self.accepted = accepted;
                Ok(())
            }
            Some(envelope::Body::HelloRejected(rejected)) => Err(ClientError::Rejected {
                code: rejected.code,
                detail: rejected.detail,
            }),
            _ => Err(ClientError::UnexpectedResponse { phase: "handshake" }),
        }
    }

    fn write_envelope(&mut self, envelope: &Envelope) -> Result<(), ClientError> {
        let mut payload = Vec::new();
        envelope
            .encode(&mut payload)
            .expect("encoding into Vec cannot fail");
        let stdin = self.stdin.as_mut().ok_or_else(|| {
            ClientError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "engine stdin is closed",
            ))
        })?;
        write_frame(stdin, &payload)?;
        Ok(())
    }

    fn read_envelope(&mut self, phase: &'static str) -> Result<Envelope, ClientError> {
        self.read_envelope_with_timeout(phase, self.response_timeout)
    }

    fn read_envelope_with_timeout(
        &mut self,
        phase: &'static str,
        timeout: Duration,
    ) -> Result<Envelope, ClientError> {
        match self.frames.recv_timeout(timeout) {
            Ok(Ok(Some(payload))) => Ok(Envelope::decode(payload.as_slice())?),
            Ok(Ok(None)) | Err(RecvTimeoutError::Disconnected) => {
                if let Some(status) = self.observe_exit()? {
                    return Err(ClientError::EngineFailure {
                        code: status.code(),
                    });
                }
                Err(ClientError::CleanEof)
            }
            Ok(Err(error)) => Err(ClientError::Frame(error)),
            Err(RecvTimeoutError::Timeout) => Err(ClientError::Timeout { phase, timeout }),
        }
    }

    fn observe_exit(&mut self) -> Result<Option<ExitStatus>, io::Error> {
        let deadline = Instant::now() + EXIT_OBSERVATION_GRACE;
        loop {
            if let Some(status) = self.child_mut()?.try_wait()? {
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn child_mut(&mut self) -> Result<&mut Child, io::Error> {
        self.child.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "engine process is unavailable")
        })
    }

    fn wait_or_terminate(&mut self) -> Result<ExitStatus, ClientError> {
        if let Ok(Some(status)) = wait_for_exit(self.child_mut()?, SHUTDOWN_GRACE) {
            return self.finish_reaped_child(status);
        }

        // Group signalling is best-effort until the directly owned child has either been
        // reaped or handed to the reaper. The child may have left the group, and an I/O
        // error while invoking `kill` must not make us drop its only wait handle.
        let _ = signal_process_group(self.process_group_id, "-TERM");
        if let Ok(Some(status)) = wait_for_exit(self.child_mut()?, SHUTDOWN_GRACE) {
            return self.finish_reaped_child(status);
        }

        let _ = signal_process_group(self.process_group_id, "-KILL");
        if let Ok(Some(status)) = wait_for_exit(self.child_mut()?, SHUTDOWN_GRACE) {
            return self.finish_reaped_child(status);
        }

        // The process-group kill cannot prove anything about a child that escaped the
        // original group. Target the Child itself, then poll only for a bounded interval.
        // Child::kill errors are followed by the same bounded observation because the
        // process may have exited concurrently.
        let _ = self.child_mut()?.kill();
        if let Ok(Some(status)) = wait_for_exit(self.child_mut()?, SHUTDOWN_GRACE) {
            return self.finish_reaped_child(status);
        }

        let child_process_id = self.handoff_live_child()?;
        let _ = terminate_remaining_process_group(self.process_group_id);
        Err(ClientError::CleanupIncomplete {
            child_process_id,
            process_group_id: self.process_group_id,
            timeout: SHUTDOWN_GRACE,
        })
    }

    fn finish_reaped_child(&mut self, status: ExitStatus) -> Result<ExitStatus, ClientError> {
        // try_wait already reaped the process, so releasing this handle cannot abandon a
        // live direct child even if descendant process-group cleanup fails afterwards.
        self.child.take();
        terminate_remaining_process_group(self.process_group_id)?;
        Ok(status)
    }

    fn handoff_live_child(&mut self) -> Result<u32, io::Error> {
        if let Ok(process_id) = self.try_handoff_child() {
            return Ok(process_id);
        }

        // A disconnected per-session reaper is not expected, but replace it before
        // retrying. try_handoff_child restores ownership on every failed send.
        self.reaper = spawn_reaper()?;
        self.try_handoff_child()
    }

    fn try_handoff_child(&mut self) -> Result<u32, io::Error> {
        let child = self
            .child
            .take()
            .expect("a running engine child must still be owned by the session");
        let process_id = child.id();
        match self.reaper.send(child) {
            Ok(()) => Ok(process_id),
            Err(error) => {
                self.child = Some(error.0);
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "engine background reaper stopped unexpectedly",
                ))
            }
        }
    }

    fn drain_stdout(&mut self) -> Result<(), ClientError> {
        match self.frames.recv_timeout(SHUTDOWN_DRAIN_TIMEOUT) {
            Ok(Ok(Some(_))) => Err(ClientError::ExtraFrameAfterShutdown),
            Ok(Ok(None)) => Ok(()),
            Ok(Err(error)) => Err(ClientError::Frame(error)),
            Err(RecvTimeoutError::Disconnected) => Err(ClientError::DecoderDisconnected),
            Err(RecvTimeoutError::Timeout) => Err(ClientError::Timeout {
                phase: "shutdown stdout drain",
                timeout: SHUTDOWN_DRAIN_TIMEOUT,
            }),
        }
    }
}

impl Drop for EngineSession {
    fn drop(&mut self) {
        self.stdin.take();
        if self.child.is_some() {
            let _ = self.wait_or_terminate();
        }
    }
}

#[cfg(test)]
mod event_sequence_tests {
    use super::*;

    #[test]
    fn sequence_exhaustion_rejects_a_repeated_u64_max_event() {
        let repeated = Envelope {
            sequence: u64::MAX,
            body: Some(envelope::Body::EngineEvent(EngineEvent {
                event_sequence: u64::MAX,
                ..Default::default()
            })),
        };
        let (frame_sender, frames) = mpsc::sync_channel(FRAME_QUEUE_CAPACITY);
        frame_sender
            .send(Ok(Some(repeated.encode_to_vec())))
            .unwrap();
        let (reaper, _reaper_receiver) = mpsc::sync_channel(1);
        let mut session = EngineSession {
            child: None,
            stdin: None,
            frames,
            response_timeout: Duration::from_secs(1),
            accepted: HelloAccepted::default(),
            last_event_sequence: u64::MAX,
            process_group_id: 0,
            reaper,
        };

        let error = session
            .read_engine_event()
            .expect_err("u64::MAX cannot immediately follow itself");

        assert!(matches!(
            error,
            ClientError::EventSequenceExhausted { previous: u64::MAX }
        ));
        assert_eq!(session.last_event_sequence, u64::MAX);
    }
}

fn spawn_reaper() -> io::Result<SyncSender<Child>> {
    let (sender, receiver) = mpsc::sync_channel::<Child>(1);
    thread::Builder::new()
        .name("diskplan-engine-reaper".into())
        .spawn(move || {
            if let Ok(mut child) = receiver.recv() {
                let _ = child.wait();
            }
        })?;
    Ok(sender)
}

pub fn handshake_with_engine(engine: &Path) -> Result<Vec<String>, ClientError> {
    let session = EngineSession::connect(engine)?;
    let capabilities = session.accepted().negotiated_capabilities.clone();
    session.shutdown()?;
    Ok(capabilities)
}

pub fn handshake_with_bound_engine(engine: &BoundEngine) -> Result<Vec<String>, ClientError> {
    let session = EngineSession::connect_bound(engine)?;
    let capabilities = session.accepted().negotiated_capabilities.clone();
    session.shutdown()?;
    Ok(capabilities)
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn terminate_remaining_process_group(process_group_id: u32) -> Result<(), ClientError> {
    if !process_group_exists(process_group_id)? {
        return Ok(());
    }
    signal_process_group(process_group_id, "-TERM")?;
    if wait_for_process_group_exit(process_group_id, SHUTDOWN_GRACE)? {
        return Ok(());
    }
    signal_process_group(process_group_id, "-KILL")?;
    if wait_for_process_group_exit(process_group_id, SHUTDOWN_GRACE)? {
        Ok(())
    } else {
        Err(ClientError::ProcessGroupCleanupIncomplete {
            process_group_id,
            timeout: SHUTDOWN_GRACE,
        })
    }
}

fn signal_process_group(process_group_id: u32, signal: &str) -> io::Result<()> {
    let group = format!("-{process_group_id}");
    let status = Command::new("/bin/kill")
        .args([signal, "--", &group])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() || !process_group_exists(process_group_id)? {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "/bin/kill {signal} failed for engine process group {process_group_id}"
        )))
    }
}

fn process_group_exists(process_group_id: u32) -> io::Result<bool> {
    let group = format!("-{process_group_id}");
    Ok(Command::new("/bin/kill")
        .args(["-0", "--", &group])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success())
}

fn wait_for_process_group_exit(process_group_id: u32, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        if !process_group_exists(process_group_id)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;

    const NONEXISTENT_PROCESS_GROUP: u32 = 2_000_000_000;

    #[test]
    fn direct_child_outside_recorded_group_is_killed_and_reaped_within_bound() {
        let child = spawn_blocking_fake_engine();
        let process_id = child.id();
        let mut session = test_session(child, spawn_reaper().unwrap());

        let started = Instant::now();
        let status = session
            .wait_or_terminate()
            .expect("direct child cleanup must complete");

        assert!(!status.success());
        assert_eq!(
            status.signal(),
            Some(9),
            "a child outside the recorded group must reach direct Child::kill"
        );
        assert!(session.child.is_none(), "the reaped Child must be released");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "direct child cleanup exceeded its bounded TERM/KILL windows"
        );
        assert!(
            !process_exists(process_id),
            "fake engine {process_id} survived direct Child::kill cleanup"
        );
    }

    #[test]
    fn failed_reaper_handoff_restores_child_ownership() {
        let child = spawn_blocking_fake_engine();
        let process_id = child.id();
        let (disconnected_reaper, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        let mut session = test_session(child, disconnected_reaper);

        let error = session
            .try_handoff_child()
            .expect_err("the disconnected reaper must reject the child");

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(
            session.child.as_ref().map(Child::id),
            Some(process_id),
            "failed handoff must restore the exact Child handle"
        );

        session.child_mut().unwrap().kill().unwrap();
        let status = wait_for_exit(session.child_mut().unwrap(), Duration::from_secs(1))
            .unwrap()
            .expect("test cleanup must reap the fake engine");
        assert!(!status.success());
        session.child.take();
    }

    fn spawn_blocking_fake_engine() -> Child {
        let mut child = Command::new("/bin/bash")
            .args(["-c", "trap '' TERM; printf r; read -r _"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("fake engine must start");
        let mut ready = [0_u8; 1];
        child
            .stdout
            .take()
            .unwrap()
            .read_exact(&mut ready)
            .expect("fake engine must install its TERM handler before blocking");
        assert_eq!(&ready, b"r");
        child
    }

    fn test_session(child: Child, reaper: SyncSender<Child>) -> EngineSession {
        let (_frame_sender, frames) = mpsc::sync_channel(FRAME_QUEUE_CAPACITY);
        EngineSession {
            child: Some(child),
            stdin: None,
            frames,
            response_timeout: Duration::from_secs(1),
            accepted: HelloAccepted::default(),
            last_event_sequence: 0,
            process_group_id: NONEXISTENT_PROCESS_GROUP,
            reaper,
        }
    }

    fn process_exists(process_id: u32) -> bool {
        Command::new("/bin/kill")
            .args(["-0", &process_id.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}
