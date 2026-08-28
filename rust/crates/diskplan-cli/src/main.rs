use std::path::{Path, PathBuf};
use std::process::Command;

use diskplan_core::handshake::{PROTOCOL_MAJOR, PROTOCOL_MINOR};

const USAGE: &str = "usage: diskplan [--handshake] [diskplan-engine]";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_else(|| "diskplan".into());
    let first = args.next();
    if first.as_deref() == Some(Path::new("--version-json").as_os_str()) {
        if args.next().is_some() {
            usage(&program);
        }
        println!(
            "{{\"component\":\"diskplan\",\"product_version\":\"{}\",\"protocol_major\":{},\"protocol_minor\":{}}}",
            env!("CARGO_PKG_VERSION"),
            PROTOCOL_MAJOR,
            PROTOCOL_MINOR
        );
        return;
    }

    let (handshake_only, engine) = match first {
        Some(first) if first == "--handshake" => (true, args.next()),
        Some(first) => (false, Some(first)),
        None => (false, None),
    };
    if args.next().is_some() {
        usage(&program);
    }

    let engine = match engine {
        Some(engine) => PathBuf::from(engine),
        None => sibling_engine().unwrap_or_else(|error| {
            eprintln!("diskplan: cannot resolve sibling engine: {error}");
            std::process::exit(1);
        }),
    };
    verify_engine_identity(&engine).unwrap_or_else(|error| {
        eprintln!("diskplan: engine identity check failed: {error}");
        std::process::exit(1);
    });
    if handshake_only {
        match diskplan::handshake_with_engine(&engine) {
            Ok(capabilities) => println!("handshake ok: {}", capabilities.join(",")),
            Err(error) => {
                eprintln!("handshake failed: {error}");
                std::process::exit(1);
            }
        }
    } else if let Err(error) = diskplan::tui::run(&engine).await {
        eprintln!("diskplan: {error}");
        std::process::exit(1);
    }
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

fn verify_engine_identity(engine: &Path) -> std::io::Result<()> {
    let output = Command::new(engine).arg("--version-json").output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(format!(
            "{} --version-json exited {}",
            engine.display(),
            output.status
        )));
    }
    if !engine_identity_matches(&output.stdout, &output.stderr) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} does not exactly match frontend version {} and protocol {}.{}",
                engine.display(),
                env!("CARGO_PKG_VERSION"),
                PROTOCOL_MAJOR,
                PROTOCOL_MINOR
            ),
        ));
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

        assert_eq!(selected, version_one.join("diskplan-engine"));
        assert_eq!(
            sibling_engine_for_loaded_executable(
                &fs::canonicalize(&active).expect("new activation path")
            )
            .expect("new active engine"),
            version_two.join("diskplan-engine")
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
}
