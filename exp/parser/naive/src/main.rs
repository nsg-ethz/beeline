use anyhow::Result;
use clap::Parser;
use core::str;
use log::{debug, error, info};
use regex::Regex;
use std::{
    io::{Read, Write}, net::{TcpListener, TcpStream}, os::fd::AsRawFd
};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value="127.0.0.1:3000")]
    address: String,

    #[arg(short, long)]
    destination: String,

    #[arg(long="remove")]
    removals: Option<Vec<String>>,
}

fn listen<F>(addr: &str, backend: &mut TcpStream, modify: F) -> Result<()> where F: Fn(&mut [u8]) -> usize {
    let listener = TcpListener::bind(addr)?;

    let (mut client, _) = listener.accept()?;
    client.set_read_timeout(Some(std::time::Duration::from_micros(100)))?;
    client.set_nodelay(true)?;

    let fd = client.as_raw_fd();
    debug!("Accepted connection {:?}", fd);

    let mut buf = [0; 2 * 8192];
    loop {        
        match client.read(&mut buf) {
            Ok(len) => {
                if len == 0 {
                    debug!("Client closed connection");
                    return Ok(());
                }

                // let new_len = modify(&mut buf[0..len]);
                let new_len = len;

                debug!("Read {} ({}) bytes from client", len, new_len);
                backend.write_all(&buf[0..new_len])?
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
    dest.set_read_timeout(Some(std::time::Duration::from_micros(100)))?;

    info!("Listening on {}", args.address);

    let re = Regex::new(r"(?<key>.+)\s*:\s*(?<val>.+)\n")?;
    let removals = args.removals
        .unwrap_or_default()
        .iter()
        .map(|s| s.to_lowercase())
        .collect::<Vec<_>>();

    let modify = move |buf: &mut [u8]| {
        let str = str::from_utf8(buf);
        let mut start = None;
        let mut end = None;
        if let Ok(str) = str {
            for m in re.captures_iter(str) {
                if let Some(key) = m.name("key") {
                    let key = key.as_str().to_lowercase();
                    if removals.contains(&key) {
                        start = m.name("val").map(|m| m.start());
                        end = m.name("val").map(|m| m.end());
                    }
                }
            }
        }

        match (start, end) {
            (Some(start), Some(end)) => {
                buf[start..end].fill(b'X');
            },
            _ => {},
        }
        
        buf.len()
    };

    loop {
        listen(&args.address, &mut dest, &modify)?;
    }
}
