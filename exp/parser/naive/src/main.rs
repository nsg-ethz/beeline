use anyhow::Result;
use clap::Parser;
use core::str;
use log::{debug, error, info};
use matcher::{dfa::Action, http::HttpMatcher};
use std::{io::{Read, Write}, net::{TcpListener, TcpStream}, os::fd::AsRawFd};

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

                let new_len = modify(&mut buf[0..len]);

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

    let s_init: u32 = 0;
    let s_any: u32 = 1;
    let mut matcher = HttpMatcher::new(s_init as u16, s_any as u16);
    // matcher.match_http_hdr("hallo", "welt")?;
    // matcher.match_http_uri("/hello/world.html")?;
    matcher.remove_http_hdr("user-agent")?;
    matcher.done_on_http_hdr_end()?;

    let mut sm = [[0u32; 256]; 100];
    let mut acts = [[Action::None; 256]; 100];

    for (from, to, c, act) in matcher.dfa.iter_transitions() {
        acts[*from as usize][*c as usize] = *act;
        sm[*from as usize][*c as usize] = *to as u32;
    }

    let modify = move |buf: &mut [u8]| {
        let str = str::from_utf8(buf);
        let mut caps = Vec::new();
        let mut cids = [0usize; 16];
        
        if let Ok(str) = str {
            let mut s = s_init;
            for (i, c) in str.chars().enumerate() {
                let action = acts[s as usize][c as usize];
                let mut ns = sm[s as usize][c as usize];
                if ns == 0 {
                    ns = sm[s as usize]['*' as usize];
                    if ns == 0 {
                        ns = s_any;
                    }
                }
                s = ns;

                match action {
                    Action::Capture(cid) => cids[cid as usize] = i,
                    Action::Match(cid) => {
                        caps.push(cids[cid as usize]..i);
                        debug!("Matched: {:?}", &str[cids[cid as usize]..i]);
                    }
                    Action::Done => {
                        debug!("Done matching.");
                        break;
                    },
                    Action::None => ()
                }
            }
        }

        if caps.len() == 1 {
            debug!("Matched packet.")
        }
        else {
            return buf.len()
        }

        let hdr_range = caps[0].clone();
        buf[hdr_range.start+11..hdr_range.end-1].fill(b'X');
        
        buf.len()
    };

    loop {
        listen(&args.address, &mut dest, &modify)?;
    }
}
