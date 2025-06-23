use anyhow::Result;
use baseline::Proxy;
use clap::Parser;
use log::info;
use std::{mem::MaybeUninit, time::Duration};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "3000")]
    port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    let mut open_obj = MaybeUninit::uninit();
    let proxy = Proxy::attach(args.port, &mut open_obj)?;

    info!("Listening on localhost:{}", args.port);
    tokio::time::sleep(Duration::from_secs(u64::MAX)).await;

    drop(proxy);

    Ok(())
}
