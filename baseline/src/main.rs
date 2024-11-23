use anyhow::Result;
use clap::Parser;
use proxy::Proxy;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value="127.0.0.1:3000")]
    address: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    let proxy = Proxy::new(args.address)?;
    proxy.listen().await?;

    Ok(())
}
