use std::mem::MaybeUninit;

use anyhow::Result;
use clap::Parser;
use libbpf_rs::{set_print, PrintLevel};
use log::{
    debug,
    warn,
    info,
};
use ebpf::{Proxy, config::Config};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value="127.0.0.1:3000")]
    address: String,

    #[arg(short, long, default_value="config/debug.yaml")]
    config: String,
}

fn print(level: PrintLevel, msg: String) {
    let msg = msg.trim_start_matches("libbpf:")
        .trim();

    match level {
        PrintLevel::Debug => debug!(target: "libbpf", "{}", msg),
        PrintLevel::Info => info!(target: "libbpf", "{}", msg),
        PrintLevel::Warn => warn!(target: "libbpf", "{}", msg),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    set_print(Some((PrintLevel::Debug, print)));

    let args = Args::parse();
    let config = std::fs::File::open(args.config)?;
    let config: Config = serde_yaml::from_reader(config)?;

    let mut open_obj = MaybeUninit::uninit();
    let proxy = Proxy::attach(&args.address, config, &mut open_obj)?;
    proxy.listen().await
}
