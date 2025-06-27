use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/proxy.bpf.c";

fn main() {
    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");
    let out = PathBuf::from(manifest_dir)
        .join("src")
        .join("bpf")
        .join("proxy.skel.rs");

    let bpf_profile = std::env::var("BPF_PROFILE").unwrap_or("0".to_string());

    let log_level = std::env::var("RUST_LOG").unwrap_or("error".to_string());
    let log_level: u32 = match log_level.to_lowercase().as_str() {
        "debug" => 2,
        "trace" => 2,
        _ => 1,
    };
    println!("cargo:rerun-if-env-changed=RUST_LOG");

    let sm = std::env::var("SM_APP").unwrap_or("mb".to_string());
    let sm: u32 = match sm.to_lowercase().as_str() {
        "sn" => 1,
        "ms" => 2,
        _ => 0,
    };
    println!("cargo:rerun-if-env-changed=SM_APP");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-D"),
            OsStr::new(format!("LOG_LEVEL={log_level}").as_str()),
            OsStr::new("-D"),
            OsStr::new(format!("BPF_PROFILE={bpf_profile}").as_str()),
            OsStr::new("-D"),
            OsStr::new(format!("SM_APP={sm}").as_str()),
            OsStr::new("-I"),
            OsStr::new("../include"),
        ])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}
