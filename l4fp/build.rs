use xbpf::build::Builder;

fn main() {
    let log_level = std::env::var("RUST_LOG").map(|s| s.to_lowercase());
    let log_level: u32 = match log_level.as_deref() {
        Ok("debug") => 2,
        Ok("trace") => 2,
        Ok("info") => 1,
        Ok("warn") => 1,
        Ok("error") => 1,
        _ => 0,
    };
    println!("cargo:rerun-if-env-changed=RUST_LOG");

    Builder::new()
        .clang_arg(["-D", &format!("LOG_LEVEL={log_level}")].iter())
        .build();
}
