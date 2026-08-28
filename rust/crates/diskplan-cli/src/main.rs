use std::path::PathBuf;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_else(|| "diskplan".into());
    let Some(first) = args.next() else {
        eprintln!(
            "usage: {} [--handshake] <diskplan-engine>",
            PathBuf::from(program).display()
        );
        std::process::exit(64);
    };
    let (handshake_only, engine) = if first == "--handshake" {
        let Some(engine) = args.next() else {
            eprintln!("usage: diskplan [--handshake] <diskplan-engine>");
            std::process::exit(64);
        };
        (true, engine)
    } else {
        (false, first)
    };
    if args.next().is_some() {
        eprintln!("usage: diskplan [--handshake] <diskplan-engine>");
        std::process::exit(64);
    }

    let engine = PathBuf::from(engine);
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
