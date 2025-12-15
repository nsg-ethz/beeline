use anyhow::Result;
use clap::Parser;
use common::config::beeline::Cidr;
use l4fp::Proxy;
use std::{mem::MaybeUninit, time::Duration};
use tracing::info;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "172.18.0.0/24")]
    cidr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let mut open_obj = MaybeUninit::uninit();

    let cidr: Cidr = args.cidr.parse().expect("Failed to parse CIDR");
    let proxy = Proxy::accelerate(cidr, &mut open_obj)?;

    info!("Accelerating {}", args.cidr);
    tokio::time::sleep(Duration::from_secs(u64::MAX)).await;

    drop(proxy);

    Ok(())
}
