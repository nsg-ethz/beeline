use anyhow::Result;
use clap::Parser;
use core::str;
use common::{
    config::{self, Config},
    parse::{http::HttpParser, Action}
};
use std::{pin::Pin, task::{Context, Poll}};
use log::{debug, error, info};
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream}
};
use pin_project_lite::pin_project;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value="127.0.0.1:3000")]
    address: String,

    #[arg(short, long, default_value="../../config/debug.yaml")]
    config: String,
}

pin_project! {
    
    struct Modifier<F> {
        #[pin]
        inner: TcpStream,

        #[pin]
        modify: F
    }
}

impl<F> Modifier<F> {

    fn new(stream: TcpStream, modify: F) -> Self {
        Self { 
            inner: stream,
            modify
        }
    }

}

impl<F> AsyncRead for Modifier<F> {

    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_read(cx, buf)
    }

}

impl<F> AsyncWrite for Modifier<F> where F: Send + Clone + Fn(&mut Vec<u8>) {
    
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let mut buf = buf.to_vec();
        let this = self.project();
        (this.modify)(&mut buf);

        this.inner.poll_write(cx, &buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }

}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();  
    let config = std::fs::File::open(args.config)?;
    let config: Config = serde_yaml::from_reader(config)?;

    let s_init: u32 = 0;
    let s_any: u32 = 1;
    let mut parser = HttpParser::new(s_init as u16, s_any as u16);

    for r in config.route {
        for (key, val) in r.r#match {
            parser.match_http_hdr(&key, &val)?;
        }
    }
    
    for hdr in args.rewrite.unwrap_or_default() {
        if let Some((key, val)) = hdr.split_once(":") {
            parser.rewrite_http_hdr(key.trim(), val.trim())?;
        }
        else {
            panic!("Invalid header format: {}", hdr);
        }
    }

    parser.done_on_http_hdr_end()?;

    let mut sm = [[0u32; 256]; 100];
    let mut acts = [[Action::None; 256]; 100];
    let mut num_matches = 0;

    for (from, to, c, act) in parser.iter_transitions() {
        acts[*from as usize][*c as usize] = *act;
        sm[*from as usize][*c as usize] = *to as u32;

        if let Action::Match(_) = act {
            num_matches += 1;
        }
    }

    info!("Listening on {}", args.address);
    let listener = TcpListener::bind(args.address).await?;

    while let Ok((ingress, _)) = listener.accept().await {
        let mut egress = TcpStream::connect(args.destination.clone()).await?;
        debug!("Connection established {}", egress.local_addr()?.port());
        let mods = parser.modifications.clone();

        tokio::spawn(async move {
            let mut mod_ingress = Modifier::new(ingress, |buf: &mut Vec<u8>| {
                let str = str::from_utf8(buf);
                if str.is_err() {
                    error!("Failed to decode request.");
                    return;
                }

                let mut str = str.unwrap().to_string();
                let mut caps = Vec::new();
                let mut cids = [0usize; 16];
                let mut s = s_init;

                for (i, c) in str.chars().enumerate() {
                    let mut action = acts[s as usize][c as usize];
                    let mut ns = sm[s as usize][c as usize];
                    if ns == 0 {
                        ns = sm[s as usize]['*' as usize];
                        action = acts[s as usize]['*' as usize];
                        if ns == 0 {
                            ns = s_any;
                            action = Action::None;
                        }
                    }
                    s = ns;
    
                    match action {
                        Action::Capture(cid) => {
                            debug!("Capturing: {:?} at {}", cid, i);
                            cids[cid as usize] = i;
                        }
                        Action::Match(cid) => {
                            caps.push((cid, cids[cid as usize]..i+1));
                            debug!("Matched: {:?}, cid: {}", &str[cids[cid as usize]..i+1], cid);
                        }
                        Action::Done => {
                            debug!("Done matching.");
                            break;
                        },
                        Action::None => ()
                    }
                }
        
                if caps.len() == num_matches {
                    debug!("Matched packet.");

                    let mut off: i32 = 0;
                    for (cid, range) in caps.into_iter() {
                        let replacement = mods.get(&cid).map(|m| m.replacement.as_str()).unwrap_or_default();
                        let tail = mods.get(&cid).map(|m| m.tail).unwrap_or(0);
                        let range = ((range.start as i32) + off) as usize .. ((range.end as i32) + off) as usize - tail as usize;

                        debug!("Replacing {:?} with {:?}, diff: {:?}", &str[range.clone()], replacement, replacement.len() as i32 - range.len() as i32);
                        off += replacement.len() as i32 - range.len() as i32;

                        str.replace_range(range, replacement);
                    }

                    *buf = str.as_bytes().to_vec();
                }
            });

            if let Err(e) = copy_bidirectional(&mut mod_ingress, &mut egress).await {
                error!("Error copying data: {:?}", e);
            }
        });
    }

    Ok(())
}
