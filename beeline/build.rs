use common::{Compiler, Config};
use libbpf_cargo::SkeletonBuilder;
use std::{env, ffi::OsStr, fs, path::PathBuf};

fn main() {
    let bpf_profile = std::env::var("BPF_PROFILE").unwrap_or("0".to_string());
    println!("cargo:rerun-if-env-changed=BPF_PROFILE");

    let log_level = std::env::var("RUST_LOG").unwrap_or("error".to_string());
    let log_level: u32 = match log_level.to_lowercase().as_str() {
        "debug" => 2,
        "trace" => 2,
        _ => 1,
    };
    println!("cargo:rerun-if-env-changed=RUST_LOG");

    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");
    let root_dir = PathBuf::from(&manifest_dir).join("..");
    let target_dir = root_dir.join("target").join("bpf");
    let base = PathBuf::from(&manifest_dir).join("src/bpf/base.bpf.c");
    let filter_dir = PathBuf::from(&manifest_dir).join("src/bpf/filter/");
    let out = PathBuf::from(&target_dir).join("proxy.bpf.c");

    println!("cargo:rerun-if-changed={}", base.to_str().unwrap());
    println!("cargo:rerun-if-changed={}", filter_dir.to_str().unwrap());

    match fs::create_dir(&target_dir) {
        Ok(_) => Ok(()),
        Err(ref e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(e),
    }
    .expect("Failed to create target/bpf");

    let mut stats = "0";
    if let Some(config) = env::var_os("CONFIG") {
        let config = PathBuf::from(&root_dir).join(config);
        let config = fs::File::open(config).expect("Failed to open config file");
        let config: Config = serde_yaml::from_reader(&config).expect("Failed to parse config");

        if config.stats {
            stats = "1";
        }

        let compiler = Compiler::new(config);
        compiler.generate(&base, &out);
    }
    println!("cargo:rerun-if-env-changed=CONFIG");

    let mut builder = SkeletonBuilder::new();
    let builder = builder.source(&out).clang_args([
        OsStr::new("-D"),
        OsStr::new(format!("LOG_LEVEL={log_level}").as_str()),
        OsStr::new("-D"),
        OsStr::new(format!("BPF_PROFILE={bpf_profile}").as_str()),
        OsStr::new("-D"),
        OsStr::new(format!("STATS={stats}").as_str()),
        OsStr::new("-I"),
        OsStr::new("../include"),
    ]);

    let out = PathBuf::from(&manifest_dir).join("src/bpf/proxy.skel.rs");
    builder.build_and_generate(&out).unwrap();
    println!("cargo:rerun-if-changed={}", out.to_str().unwrap());
}
