use std::path::{Path, PathBuf};

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
    let executable = std::fs::canonicalize(std::env::current_exe()?)?;
    let directory = executable.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "launcher executable has no parent directory",
        )
    })?;
    Ok(directory.join("diskplan-engine"))
}

fn usage(program: &std::ffi::OsStr) -> ! {
    eprintln!("{}: {USAGE}", PathBuf::from(program).display());
    std::process::exit(64);
}
