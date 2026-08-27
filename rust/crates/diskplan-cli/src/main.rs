use std::path::PathBuf;

fn main() {
    let mut args = std::env::args_os();
    let program = args.next().unwrap_or_else(|| "diskplan".into());
    let Some(engine) = args.next() else {
        eprintln!(
            "usage: {} <diskplan-engine>",
            PathBuf::from(program).display()
        );
        std::process::exit(64);
    };
    if args.next().is_some() {
        eprintln!("usage: diskplan <diskplan-engine>");
        std::process::exit(64);
    }
    match diskplan::handshake_with_engine(&PathBuf::from(engine)) {
        Ok(capabilities) => println!("handshake ok: {}", capabilities.join(",")),
        Err(error) => {
            eprintln!("handshake failed: {error}");
            std::process::exit(1);
        }
    }
}
