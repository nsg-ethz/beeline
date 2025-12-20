use anyhow::Result;
use beeline::Proxy;
use clap::Parser;
use common::config::beeline::Config;
use std::{env, mem::MaybeUninit, net::SocketAddr};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    address: Option<SocketAddr>,

    #[arg(short, long)]
    config: Option<String>,

    #[arg(short, long, action)]
    validate: bool,

    #[arg(long)]
    tls: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();

    let config = args
        .config
        .or(env::var("CONFIG").ok())
        .unwrap_or(String::from("config/beeline/debug.yaml"));

    let config = std::fs::File::open(config)?;
    let config: Config = serde_yaml::from_reader(&config).expect("Failed to parse config");

    let addr = args
        .address
        .or(config.socket)
        .unwrap_or("127.0.0.1:3000".parse().unwrap());

    let mut open_obj = MaybeUninit::uninit();
    let proxy = Proxy::attach(&addr, args.tls, config, &mut open_obj)?;

    if !args.validate {
        proxy.listen().await
    } else {
        Ok(())
    }
}
