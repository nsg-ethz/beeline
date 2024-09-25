use anyhow::Result;
use clap::Parser;
use core::str;
use std::{pin::Pin, task::{Context, Poll}};
use log::{debug, error, info};
use matcher::{dfa::Action, http::HttpMatcher};
use tokio::{
    io::{copy_bidirectional, AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream}
};
use pin_project_lite::pin_project;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value="127.0.0.1:3000")]
    address: String,

    #[arg(short, long)]
    destination: String,

    #[arg(long="remove")]
    removals: Option<Vec<String>>,
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

impl<F> AsyncRead for Modifier<F> where F: Send + Clone + Fn(&mut [u8]) -> usize {

    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let res = this.inner.poll_read(cx, buf);

        let buf = buf.filled_mut();
        (this.modify)(buf);
        res
    }

}

impl<F> AsyncWrite for Modifier<F> {
    
        fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
            self.project().inner.poll_write(cx, buf)
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

    info!("Listening on {}", args.address);
    let listener = TcpListener::bind(args.address).await?;

    while let Ok((inbound, _)) = listener.accept().await {
        let mut mod_inbound = Modifier::new(inbound, modify.clone());
        let mut outbound = TcpStream::connect(args.destination.clone()).await?;
        debug!("Connection established {}", outbound.local_addr()?.port());

        tokio::spawn(async move {
            if let Err(e) = copy_bidirectional(&mut mod_inbound, &mut outbound).await {
                error!("Error copying data: {:?}", e);
            }
        });
    }

    Ok(())
}
