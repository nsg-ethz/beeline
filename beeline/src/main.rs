use anyhow::Result;
use beeline::Proxy;
use clap::Parser;
use common::Config;
use std::mem::MaybeUninit;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:3000")]
    address: String,

    #[arg(short, long, default_value = "config/beeline/debug.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    let config = std::fs::File::open(args.config)?;
    let config: Config = serde_yaml::from_reader(config)?;

    let mut open_obj = MaybeUninit::uninit();
    let proxy = Proxy::attach(&args.address, config, &mut open_obj)?;
    proxy.listen().await
}
