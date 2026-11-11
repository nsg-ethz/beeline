use anyhow::Result;
use beeline::Proxy;
use clap::Parser;
use common::config::beeline::{Config, TlsConfig};
use std::{env, mem::MaybeUninit, net::SocketAddr, time::Duration};

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    address: Option<SocketAddr>,

    #[arg(short, long)]
    config: Option<String>,

    #[arg(short, long, action)]
    validate: bool,

    /// Load the data plane 30 times and report the average verifier stats of every program
    #[arg(long, action)]
    verify: bool,

    #[arg(long)]
    tls: Option<SocketAddr>,

    /// Seconds that SIGUSR1 waits for the open connections to close before it exits
    #[arg(long, default_value_t = 600)]
    drain_time: u64,

    /// The pid of the beeline that this one replaces. It gets SIGUSR1 once this one listens
    #[arg(long)]
    replace: Option<i32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        // eprintln! panics on a closed stderr, which kills the task that logs
        .log_internal_errors(false)
        .init();

    let args = Args::parse();

    let config = args
        .config
        .or(env::var("CONFIG").ok())
        // the data plane is compiled for this config
        .unwrap_or(String::from(env!("BEELINE_CONFIG")));

    let config = std::fs::File::open(config)?;
    let config: Config = serde_yaml::from_reader(&config).expect("Failed to parse config");

    let addr = args
        .address
        .or(config.socket)
        .unwrap_or("127.0.0.1:3000".parse().unwrap());

    let tls = if let Some(socket) = args.tls {
        Some(TlsConfig {
            socket,
            cert: String::from("res/pem/cert.pem"),
            key: String::from("res/pem/key.pem"),
        })
    } else {
        config.tls.clone()
    };

    if args.verify {
        return Proxy::verify(addr, tls, config, 30);
    }

    let mut open_obj = MaybeUninit::uninit();
    let mut proxy = Proxy::attach(&addr, tls, config, &mut open_obj, false)?;
    proxy.drain_time = Duration::from_secs(args.drain_time);
    proxy.replace = args.replace;

    if !args.validate {
        proxy.listen().await
    } else {
        Ok(())
    }
}
