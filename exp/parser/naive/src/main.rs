use anyhow::Result;
use clap::Parser;
use core::str;
use log::{debug, info, warn};
use matcher::{dfa::Action, http::HttpMatcher};
use std::{io::{Read, Write}, marker::Send, net::{TcpStream, SocketAddr}, os::fd::AsRawFd, thread};
use socket2::{Domain, Socket, Type};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value="127.0.0.1:3000")]
    address: String,

    #[arg(short, long)]
    destination: String,

    #[arg(long="remove")]
    removals: Option<Vec<String>>,
}

fn listen<F>(addr: &str, dest: &str, modify: F) -> Result<()> where F: Send + Clone + Fn(&mut [u8]) -> usize {
    let addr: SocketAddr = addr.parse()?;
        
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;

    socket.listen(4096)?;

    thread::scope(|s| {
        loop {
            let mut backend = TcpStream::connect(dest).unwrap();
            backend.set_nodelay(true).unwrap();
            backend.set_read_timeout(Some(std::time::Duration::from_micros(100))).unwrap();

            let (mut client, _) = socket.accept().unwrap();
            client.set_read_timeout(Some(std::time::Duration::from_micros(100))).unwrap();
            client.set_nodelay(true).unwrap();

            let mod_fn = modify.clone();

            s.spawn(move || {
                let fd = client.as_raw_fd();
                debug!("Accepted connection {:?}", fd);

                let mut buf = [0; 2 * 8192];
                loop {        
                    match client.read(&mut buf) {
                        Ok(len) => {
                            if len == 0 {
                                debug!("Client closed connection");
                                return;
                            }

                            let new_len = mod_fn(&mut buf[0..len]);

                            debug!("Read {} ({}) bytes from client", len, new_len);
                            backend.write_all(&buf[0..new_len])
                                .unwrap();
                        },
                        Err(e) => warn!("Error reading from client: {}", e),
                    }

                    buf.fill(0);
                    match backend.read(&mut buf) {
                        Ok(len) => {
                            debug!("Read {} bytes from backend", len);
                            client.write_all(&buf[0..len])
                                .unwrap();
                        },
                        Err(e) => warn!("Error reading from backend: {}", e),
                    }

                }
            });
        }
    });

    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

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

    listen(&args.address, &args.destination, &modify)?;

    Ok(())
}
