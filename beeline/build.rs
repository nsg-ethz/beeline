use std::env;
use std::ffi::OsStr;
use std::path::PathBuf;

use libbpf_cargo::SkeletonBuilder;

const SRC: &str = "src/bpf/proxy.bpf.c";

fn main() {
    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set in build script");
    let out = PathBuf::from(manifest_dir)
        .join("src")
        .join("bpf")
        .join("proxy.skel.rs");

    let log_level = std::env::var("RUST_LOG").unwrap_or("error".to_string());
    let log_level = if log_level == "debug" {
        "2"
    } else {
        "1"
    };
    println!("cargo:rerun-if-env-changed=RUST_LOG");

    SkeletonBuilder::new()
        .source(SRC)
        .clang_args([
            OsStr::new("-D"),
            OsStr::new(format!("LOG_LEVEL={log_level}").as_str()),
            OsStr::new("-I"),
            OsStr::new("src/bpf/vmlinux.h")
        ])
        .build_and_generate(&out)
        .unwrap();
    println!("cargo:rerun-if-changed={SRC}");
}