use common::{config::beeline::Config, Compiler};
use std::{env, ffi::OsString, fs, path::PathBuf};
use xbpf::build::Builder;

fn main() {
    let bpf_profile = std::env::var("BPF_PROFILE").unwrap_or("0".to_string());
    let bpf_profile: u32 = match bpf_profile.to_lowercase().as_str() {
        "true" => 1,
        "1" => 1,
        _ => 0,
    };
    println!("cargo:rerun-if-env-changed=BPF_PROFILE");

    let log_level = std::env::var("BPF_LOG")
        .or(std::env::var("RUST_LOG"))
        .map(|s| s.to_lowercase());
    let log_level: u32 = match log_level.as_deref() {
        Ok("debug") => 2,
        Ok("trace") => 2,
        Ok("info") => 1,
        Ok("warn") => 1,
        Ok("error") => 1,
        _ => 0,
    };
    println!("cargo:rerun-if-env-changed=BPF_LOG");
    println!("cargo:rerun-if-env-changed=RUST_LOG");

    let manifest_dir =
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR must be set in build script");
    let root_dir = PathBuf::from(&manifest_dir).join("..");
    let base = PathBuf::from(&manifest_dir).join("src/bpf/base.bpf.c");
    let filter_dir = PathBuf::from(&manifest_dir).join("src/bpf/filter/");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("proxy.bpf.c");

    println!("cargo:rerun-if-changed={}", base.to_str().unwrap());
    println!("cargo:rerun-if-changed={}", filter_dir.to_str().unwrap());

    let config = env::var("CONFIG").unwrap_or(String::from("config/beeline/debug.yaml"));
    let config = root_dir
        .join(config)
        .canonicalize()
        .expect("Failed to find config file");
    println!("cargo:rerun-if-env-changed=CONFIG");
    println!("cargo:rerun-if-changed={}", config.display());
    // the data plane only enforces this config, tests have to load the same one
    println!("cargo:rustc-env=BEELINE_CONFIG={}", config.display());

    let config = fs::File::open(config).expect("Failed to open config file");
    let config: Config = serde_yaml::from_reader(&config).expect("Failed to parse config");
    let stats = config.stats as u32;
    Compiler::new(config).generate(&base, &out);

    let mut args = beeper::build::clang_args();
    args.extend(
        [
            format!("LOG_LEVEL={log_level}"),
            format!("BPF_PROFILE={bpf_profile}"),
            format!("STATS={stats}"),
        ]
        .into_iter()
        .flat_map(|def| [OsString::from("-D"), OsString::from(def)]),
    );

    // the files below src are templates, only the generated program is compiled
    Builder::new()
        .sources_with_suffix("template-only")
        .source(&out)
        .clang_arg(args.iter())
        .build();
}
