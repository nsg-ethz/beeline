use anyhow::Result;
use clap::Parser;
use log::{debug, error, info};
use std::{
    io::{Read, Write}, net::{TcpListener, TcpStream}, os::fd::AsRawFd
};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value="127.0.0.1")]
    address: String,

    #[arg(short, long, default_value="3000")]
    port: u16,

    #[arg(short, long)]
    destination: String,

    #[arg(long="remove")]
    removals: Option<Vec<String>>,
}

fn listen(addr: &str, backend: &mut TcpStream) -> Result<()> {
    let listener = TcpListener::bind(addr)?;

    let (mut client, _) = listener.accept()?;
    client.set_nodelay(true)?;

    let fd = client.as_raw_fd();
    debug!("Accepted connection {:?}", fd);

    let mut buf = [0; 8192];
    loop {        
        match client.read(&mut buf) {
            Ok(len) => {
                if len == 0 {
                    debug!("Client closed connection");
                    return Ok(());
                }

                debug!("Read {} bytes from client", len);
                backend.write_all(&buf[0..len])?
            },
            Err(e) => error!("Error reading from client: {}", e),
        }

        buf.fill(0);
        match backend.read(&mut buf) {
            Ok(len) => {
                debug!("Read {} bytes from backend", len);
                client.write_all(&buf[0..len])?
            },
            Err(e) => error!("Error reading from backend: {}", e),
        }

    }
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    let mut dest = TcpStream::connect(args.destination)?;
    dest.set_nodelay(true)?;

    let addr = format!("{}:{}", args.address, args.port);
    info!("Listening on {}", addr);

    loop {
        listen(&addr, &mut dest)?;
    }
}
