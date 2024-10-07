use clap::Parser;

mod http;
mod rpc;

#[derive(Parser)]
struct Args {
    #[arg(long, default_value="127.0.0.1:8000")]
    http: String,

    #[arg(long, default_value="127.0.0.1:50051")]
    rpc: String,
    
    #[arg(short='M', long="meta")]
    meta_data: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let args = Args::parse();

    let http = http::listen(args.http, args.meta_data.clone());

    let default_rpc_meta = vec!["signature: server".to_string()];
    let rpc = rpc::listen(args.rpc, args.meta_data.unwrap_or(default_rpc_meta));

    tokio::try_join!(http, rpc)?;

    Ok(())
}