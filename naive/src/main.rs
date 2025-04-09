use anyhow::Result;
use clap::Parser;
use common::Config;
use naive::Proxy;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:3000")]
    address: String,

    #[arg(short, long, default_value = "config/debug.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    let config = std::fs::File::open(args.config)?;
    let config: Config = serde_yaml::from_reader(config)?;

    let proxy = Proxy::new(args.address, config)?;
    proxy.listen().await?;

    Ok(())
}
