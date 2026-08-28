use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args_os().skip(1);
    let protoc = PathBuf::from(
        args.next()
            .ok_or("usage: proto-codegen <protoc> <out-dir>")?,
    );
    let out_dir = PathBuf::from(
        args.next()
            .ok_or("usage: proto-codegen <protoc> <out-dir>")?,
    );
    if args.next().is_some() {
        return Err("usage: proto-codegen <protoc> <out-dir>".into());
    }

    std::fs::create_dir_all(&out_dir)?;
    let mut config = prost_build::Config::new();
    config.protoc_executable(protoc);
    config.out_dir(out_dir);
    // Envelope.Body intentionally carries the complete semantic event union.
    // Its large variant is generated code and stays inline to keep the public
    // prost API stable across the protocol 1.3 schema update.
    config.enum_attribute(
        ".diskplan.v1.Envelope.body",
        "#[allow(clippy::large_enum_variant)]",
    );
    config.compile_protos(&["proto/diskplan/v1/ipc.proto"], &["proto"])?;
    Ok(())
}
