use std::env;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set in build script");

    let path = PathBuf::from(manifest_dir)
        .join("..")
        .join("..")
        .join("proto")
        .join("echo.proto");

    tonic_build::compile_protos(path)?;
    Ok(())
}