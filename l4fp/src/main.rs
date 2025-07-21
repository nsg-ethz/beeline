use anyhow::Result;
use clap::Parser;
use common::config::Cidr;
use l4fp::Proxy;
use log::info;
use std::{mem::MaybeUninit, time::Duration};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "172.18.0.0/24")]
    cidr: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    let mut open_obj = MaybeUninit::uninit();

    let cidr: Cidr = args.cidr.parse().expect("Failed to parse CIDR");
    let proxy = Proxy::accelerate(cidr, &mut open_obj)?;

    info!("Accelerating {}", args.cidr);
    tokio::time::sleep(Duration::from_secs(u64::MAX)).await;

    drop(proxy);

    Ok(())
}
