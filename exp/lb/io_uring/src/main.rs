mod http;
mod proxy;

use anyhow::Result;
use clap::Parser;
use std::collections::HashMap;

use crate::proxy::Proxy;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
    #[clap(short, long)]
    pub address: String,

    #[clap(short, long, value_delimiter = ' ', num_args = 1..)]
    pub backends: Vec<String>,
}

fn main() -> Result<()> {
    env_logger::init();
    
    let args = Args::parse();

    let backends: HashMap<String, String> = args.backends
        .iter()
        .enumerate()
        .map(|(i, addr)| (format!("/server{}", i+1), addr.to_owned()))
        .collect();

    let mut proxy = Proxy::new(args.address, backends)?;
    proxy.listen()?;

    Ok(())
}
