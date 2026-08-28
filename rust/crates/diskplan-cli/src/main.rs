use std::path::{Path, PathBuf};

use diskplan::batch::ProtocolBatchEngineClient;
use diskplan::cli::{CommandLine, USAGE};
use diskplan::{BoundEngine, batch, cli};
use diskplan_core::handshake::{PROTOCOL_MAJOR, PROTOCOL_MINOR};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_else(|| "diskplan".into());
    let command = cli::parse(args).unwrap_or_else(|error| {
        eprintln!("diskplan: {}", error.detail());
        usage(&program);
    });
    if command == CommandLine::VersionJson {
        print_version_json();
        return;
    }
    let batch_mode = matches!(&command, CommandLine::Batch(_));

    let engine = match &command {
        CommandLine::Handshake { engine } | CommandLine::Interactive { engine } => engine.clone(),
        CommandLine::Batch(_) | CommandLine::VersionJson => None,
    };
    let engine = match engine {
        Some(engine) => engine,
        None => sibling_engine()
            .map_err(|error| setup_io_failure("cannot resolve sibling engine", error))
            .unwrap_or_else(|failure| abort_engine_setup(batch_mode, failure)),
    };
    let bound_engine = BoundEngine::open(&engine)
        .map_err(|error| setup_io_failure("cannot bind engine object", error))
        .unwrap_or_else(|failure| abort_engine_setup(batch_mode, failure));
    verify_engine_identity(&bound_engine, &engine)
        .unwrap_or_else(|failure| abort_engine_setup(batch_mode, failure));
    match command {
        CommandLine::Handshake { .. } => match diskplan::handshake_with_bound_engine(&bound_engine)
        {
            Ok(capabilities) => println!("handshake ok: {}", capabilities.join(",")),
            Err(error) => {
                eprintln!("handshake failed: {error}");
                std::process::exit(1);
            }
        },
        CommandLine::Interactive { .. } => {
            if let Err(error) = diskplan::tui::run_bound(&bound_engine).await {
                eprintln!("diskplan: {error}");
                std::process::exit(1);
            }
        }
        CommandLine::Batch(options) => {
            // Protocol 1.4 replaces this fail-closed adapter with the authoritative
            // scan -> plan -> dry-run client. Protocol 1.3 must never pass India by
            // presenting scan finalization as an empty plan.
            let mut client = ProtocolBatchEngineClient;
            if let Err(error) = batch::run(&mut client, &options, &mut std::io::stdout().lock()) {
                eprintln!("diskplan: {error}");
                std::process::exit(error.exit_code());
            }
        }
        CommandLine::VersionJson => unreachable!("version command returned before engine binding"),
    }
}

#[derive(Debug, thiserror::Error)]
enum EngineSetupFailure {
    #[error("{context}: {source}")]
    Unavailable {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("{context}: {detail}")]
    InvalidIdentityOrProtocol {
        context: &'static str,
        detail: String,
    },
    #[error("{context}: {source}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },
}

fn setup_io_failure(context: &'static str, source: std::io::Error) -> EngineSetupFailure {
    match source.kind() {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied => {
            EngineSetupFailure::Unavailable { context, source }
        }
        _ => EngineSetupFailure::Io { context, source },
    }
}

fn abort_engine_setup(batch_mode: bool, failure: EngineSetupFailure) -> ! {
    eprintln!("diskplan: {failure}");
    let exit_code = engine_setup_exit_code(batch_mode, &failure);
    std::process::exit(exit_code);
}

const fn engine_setup_exit_code(batch_mode: bool, failure: &EngineSetupFailure) -> i32 {
    if batch_mode {
        match failure {
            EngineSetupFailure::Unavailable { .. } => 69,
            EngineSetupFailure::InvalidIdentityOrProtocol { .. } => 70,
            EngineSetupFailure::Io { .. } => 74,
        }
    } else {
        1
    }
}

fn print_version_json() {
    println!(
        "{{\"component\":\"diskplan\",\"product_version\":\"{}\",\"protocol_major\":{},\"protocol_minor\":{}}}",
        env!("CARGO_PKG_VERSION"),
        PROTOCOL_MAJOR,
        PROTOCOL_MINOR
    );
}

fn sibling_engine() -> std::io::Result<PathBuf> {
    // Protected property: an already-loaded frontend remains paired with its own
    // version across activation changes. The kernel path anchors frontend object
    // identity; the exact identity probe below separately checks the sibling's
    // component, product version, and protocol before either operational launch.
    sibling_engine_for_loaded_executable(&loaded_executable_path()?)
}

fn sibling_engine_for_loaded_executable(executable: &Path) -> std::io::Result<PathBuf> {
    let directory = executable.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "launcher executable has no parent directory",
        )
    })?;
    Ok(directory.join("diskplan-engine"))
}

#[cfg(target_os = "macos")]
fn loaded_executable_path() -> std::io::Result<PathBuf> {
    // `current_exe` may preserve the activation symlink used at launch. Resolving that
    // path after activation changes can therefore select a different version. The
    // kernel process path names the executable vnode already loaded by this process.
    const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

    #[link(name = "proc")]
    unsafe extern "C" {
        fn proc_pidpath(pid: i32, buffer: *mut std::ffi::c_void, buffersize: u32) -> i32;
    }

    let mut buffer = [0_u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: `buffer` is writable for the exact size passed to `proc_pidpath`, and
    // `std::process::id` is the current live process.
    let length = unsafe {
        proc_pidpath(
            std::process::id() as i32,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        return Err(std::io::Error::last_os_error());
    }
    let length = usize::try_from(length).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "kernel returned an invalid executable path length",
        )
    })?;
    if length >= buffer.len() || buffer[length] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "kernel returned an unterminated executable path",
        ));
    }

    use std::os::unix::ffi::OsStringExt;
    let path = PathBuf::from(std::ffi::OsString::from_vec(buffer[..length].to_vec()));
    if !path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "kernel returned a non-absolute executable path",
        ));
    }
    Ok(path)
}

#[cfg(not(target_os = "macos"))]
fn loaded_executable_path() -> std::io::Result<PathBuf> {
    std::fs::canonicalize(std::env::current_exe()?)
}

fn expected_engine_identity() -> String {
    format!(
        "{{\"component\":\"diskplan-engine\",\"product_version\":\"{}\",\"protocol_major\":{},\"protocol_minor\":{}}}\n",
        env!("CARGO_PKG_VERSION"),
        PROTOCOL_MAJOR,
        PROTOCOL_MINOR
    )
}

fn verify_engine_identity(engine: &BoundEngine, label: &Path) -> Result<(), EngineSetupFailure> {
    let output = engine
        .output(&[std::ffi::OsStr::new("--version-json")])
        .map_err(|error| setup_io_failure("engine identity probe failed", error))?;
    engine
        .revalidate()
        .map_err(|error| setup_io_failure("engine identity revalidation failed", error))?;
    if !output.status.success() {
        return Err(EngineSetupFailure::InvalidIdentityOrProtocol {
            context: "engine identity probe exited unsuccessfully",
            detail: format!(
                "{} --version-json exited {}",
                label.display(),
                output.status
            ),
        });
    }
    if !engine_identity_matches(&output.stdout, &output.stderr) {
        return Err(EngineSetupFailure::InvalidIdentityOrProtocol {
            context: "engine identity or protocol is invalid",
            detail: format!(
                "{} does not exactly match frontend version {} and protocol {}.{}",
                label.display(),
                env!("CARGO_PKG_VERSION"),
                PROTOCOL_MAJOR,
                PROTOCOL_MINOR
            ),
        });
    }
    Ok(())
}

fn engine_identity_matches(stdout: &[u8], stderr: &[u8]) -> bool {
    stderr.is_empty() && stdout == expected_engine_identity().as_bytes()
}

fn usage(program: &std::ffi::OsStr) -> ! {
    eprintln!("{}: {USAGE}", PathBuf::from(program).display());
    std::process::exit(64);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn batch_engine_setup_failures_use_stable_exit_classes() {
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied,
        ] {
            let failure = setup_io_failure("fixture unavailable", std::io::Error::from(kind));
            assert_eq!(engine_setup_exit_code(true, &failure), 69);
        }
        for kind in [
            std::io::ErrorKind::InvalidData,
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::Other,
        ] {
            let failure = setup_io_failure("fixture I/O", std::io::Error::from(kind));
            assert_eq!(engine_setup_exit_code(true, &failure), 74);
        }
        for context in [
            "engine identity probe exited unsuccessfully",
            "engine identity is invalid",
            "engine protocol is invalid",
        ] {
            let failure = EngineSetupFailure::InvalidIdentityOrProtocol {
                context,
                detail: "fixture rejection".into(),
            };
            assert_eq!(engine_setup_exit_code(true, &failure), 70);
        }
    }

    #[test]
    fn interactive_and_handshake_setup_failures_keep_legacy_status() {
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::InvalidData,
            std::io::ErrorKind::Other,
        ] {
            let failure = setup_io_failure("fixture setup", std::io::Error::from(kind));
            assert_eq!(engine_setup_exit_code(false, &failure), 1);
        }
        let failure = EngineSetupFailure::InvalidIdentityOrProtocol {
            context: "engine protocol is invalid",
            detail: "fixture rejection".into(),
        };
        assert_eq!(engine_setup_exit_code(false, &failure), 1);
    }

    #[cfg(unix)]
    #[test]
    fn activation_switch_does_not_retarget_loaded_frontend_sibling() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().expect("temporary install root");
        let versions = root.path().join("libexec/diskplan");
        let version_one = versions.join("0.1.0");
        let version_two = versions.join("0.2.0");
        fs::create_dir_all(&version_one).expect("first version directory");
        fs::create_dir_all(&version_two).expect("second version directory");
        for version in [&version_one, &version_two] {
            fs::write(version.join("diskplan"), []).expect("frontend fixture");
            fs::write(version.join("diskplan-engine"), []).expect("engine fixture");
        }

        let bin = root.path().join("bin");
        fs::create_dir(&bin).expect("bin directory");
        let active = bin.join("diskplan");
        symlink(version_one.join("diskplan"), &active).expect("initial activation");

        // This canonical path models the executable-object path captured by
        // `proc_pidpath` after the old frontend has already been loaded.
        let loaded_frontend = fs::canonicalize(&active).expect("loaded frontend path");
        let selected = sibling_engine_for_loaded_executable(&loaded_frontend)
            .expect("engine next to loaded frontend");

        let replacement = bin.join(".diskplan-link.next");
        symlink(version_two.join("diskplan"), &replacement).expect("replacement activation");
        fs::rename(&replacement, &active).expect("atomic activation switch");

        assert_eq!(
            selected,
            fs::canonicalize(version_one.join("diskplan-engine"))
                .expect("canonical first engine path")
        );
        assert_eq!(
            sibling_engine_for_loaded_executable(
                &fs::canonicalize(&active).expect("new activation path")
            )
            .expect("new active engine"),
            fs::canonicalize(version_two.join("diskplan-engine"))
                .expect("canonical second engine path")
        );
    }

    #[test]
    fn sibling_identity_contract_rejects_any_difference() {
        let expected = expected_engine_identity();
        assert!(engine_identity_matches(expected.as_bytes(), b""));
        assert!(!engine_identity_matches(
            expected.replace("diskplan-engine", "diskplan").as_bytes(),
            b""
        ));
        assert!(!engine_identity_matches(
            expected
                .replace(env!("CARGO_PKG_VERSION"), "999.0.0")
                .as_bytes(),
            b""
        ));
        assert!(!engine_identity_matches(
            expected.trim_end().as_bytes(),
            b""
        ));
        assert!(!engine_identity_matches(
            expected.as_bytes(),
            b"unexpected diagnostics"
        ));
    }

    #[test]
    fn identity_probe_rejection_and_mismatch_are_typed_invalid() {
        let root = tempfile::tempdir().expect("temporary identity-probe root");
        for (source, expected_context) in [
            (
                Path::new("/usr/bin/false"),
                "engine identity probe exited unsuccessfully",
            ),
            (
                Path::new("/usr/bin/true"),
                "engine identity or protocol is invalid",
            ),
        ] {
            let engine = root.path().join(
                source
                    .file_name()
                    .expect("identity fixture executable name"),
            );
            fs::copy(source, &engine).expect("copy identity fixture executable");
            fs::set_permissions(&engine, fs::Permissions::from_mode(0o755))
                .expect("set identity fixture mode");
            let bound = BoundEngine::open(&engine).expect("bind identity fixture");
            let failure = verify_engine_identity(&bound, &engine)
                .expect_err("identity fixture must not match the sibling contract");
            assert!(matches!(
                &failure,
                EngineSetupFailure::InvalidIdentityOrProtocol { context, .. }
                    if *context == expected_context
            ));
            assert_eq!(engine_setup_exit_code(true, &failure), 70);
            assert_eq!(engine_setup_exit_code(false, &failure), 1);
        }
    }

    #[test]
    fn bound_engine_launches_probe_object_after_path_replacement() {
        let root = tempfile::tempdir().expect("temporary engine root");
        let engine = root.path().join("diskplan-engine");
        fs::copy(
            std::env::current_exe().expect("current test executable"),
            &engine,
        )
        .expect("copy original executable");
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o755))
            .expect("set original executable mode");
        let bound = BoundEngine::open(&engine).expect("bind original engine object");
        let probe = bound
            .output(&[std::ffi::OsStr::new("--help")])
            .expect("launch bound probe object");
        assert!(probe.status.success());

        let replacement = root.path().join("replacement");
        fs::copy("/usr/bin/false", &replacement).expect("copy replacement executable");
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o755))
            .expect("set replacement executable mode");
        let retained = root.path().join("retained-probe-object");
        fs::rename(&engine, &retained).expect("retain original engine link policy");
        fs::rename(&replacement, &engine).expect("replace original engine path");

        let output = bound
            .output(&[std::ffi::OsStr::new("--help")])
            .expect("launch the retained probe object");
        assert!(output.status.success());
    }

    #[test]
    fn bound_engine_revalidation_rejects_in_place_content_drift() {
        use std::io::Write;

        let root = tempfile::tempdir().expect("temporary engine root");
        let engine = root.path().join("diskplan-engine");
        fs::copy(
            std::env::current_exe().expect("current test executable"),
            &engine,
        )
        .expect("copy original executable");
        fs::set_permissions(&engine, fs::Permissions::from_mode(0o755))
            .expect("set original executable mode");
        let bound = BoundEngine::open(&engine).expect("bind original engine object");

        let mut writer = fs::OpenOptions::new()
            .append(true)
            .open(&engine)
            .expect("open bound engine for test mutation");
        writer.write_all(b"drift").expect("mutate engine content");
        writer.sync_all().expect("sync engine mutation");

        let error = bound
            .revalidate()
            .expect_err("content drift must invalidate bound engine");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    }
}
