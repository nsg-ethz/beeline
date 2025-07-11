use anyhow::{bail, Result};
use beeline::Proxy;
use clap::Parser;
use common::Config;
use std::{env, mem::MaybeUninit};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:3000")]
    address: String,

    #[arg(short, long)]
    config: Option<String>,

    #[arg(short, long, default_value = "false")]
    build_only: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    let config = args.config.or(env::var("CONFIG").ok());
    if config.is_none() {
        bail!("Neither CONFIG env variable nor config option specified");
    }
    let config = std::fs::File::open(config.unwrap())?;
    let config: Config = serde_yaml::from_reader(&config).expect("Failed to parse Envoy config");

    let mut open_obj = MaybeUninit::uninit();
    let proxy = Proxy::attach(&args.address, config, &mut open_obj)?;
    proxy.listen().await
}
