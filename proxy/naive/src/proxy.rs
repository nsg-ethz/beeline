use anyhow::{bail, Result};
use common::{
    config::{Config, Destination},
    parse::{http::HttpParser, Action}
};
use log::{debug, error, info};
use core::str;
use std::{collections::HashMap, net::SocketAddr};
use pin_project_lite::pin_project;
use std::{pin::Pin, task::{Context, Poll}};
use tokio::{io::{copy, AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf}, net::{TcpListener, TcpStream}
};

const S_INIT: u32 = 0;
const S_ANY: u32 = 1;

pin_project! {
    
    struct Modifier<F> {
        #[pin]
        inner: TcpStream,

        #[pin]
        modify: F,

        #[pin]
        fid: u8,
    }
}

impl<F> Modifier<F> {

    fn new(stream: TcpStream, modify: F) -> Self {
        Self { 
            inner: stream,
            modify,
            fid: 0,
        }
    }

}

impl<F> AsyncRead for Modifier<F> {

    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        let res = self.project().inner.poll_read(cx, buf);

        if buf.filled().len() == 0 {
            return Poll::Ready(Ok(()));
        }

        res
    }

}

impl<F> AsyncWrite for Modifier<F> where F: Send + Clone + Fn(&mut Vec<u8>) -> u8 {
    
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        let mut buf = buf.to_vec();
        let mut this = self.project();
        let fid = (this.modify)(&mut buf);
        this.fid.set(fid);

        this.inner.poll_write(cx, &buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }

}

#[derive(Debug, Clone)]
struct Filter {
    fid: usize,
    num_patterns: usize,
    mods: Vec<u8>
}

pub struct Proxy {
    pub address: SocketAddr,
    pub config: Config,
    parser: HttpParser,
    filters: Vec<Filter>,
    upstreams: Vec<TcpStream>,
    downstreams: Vec<TcpStream>,
}

impl Proxy {

    pub fn new(address: String, config: Config) -> Result<Self> {
        let mut parser = HttpParser::new(S_INIT as u16, S_ANY as u16);
        let mut mods = HashMap::new();
        let mut filters = Vec::new();

        // filters from the config are split into two parts:
        // request and response filters
        let mut num_filters = 0;
        for filter in &config.spec.http {
            // first the req filter is added
            // it is added anyways, because it dictates where to route traffic to
            let fid = num_filters + 1;
            parser.start_new_filter(fid as u8);
            num_filters += 1;

            for (key, val) in &filter.patterns {
                parser.match_http_hdr(&key, &val)?;
            }
        
            let req = filter.mods
                .clone()
                .and_then(|h| h.request);

            let mids = req.and_then(|req| {
                let remove = req.remove.unwrap_or_default()
                    .iter()
                    .map(|key| {
                        // only add a modification once to the dfa
                        if let Some(mid) = mods.get(key) {
                            *mid
                        }
                        else {
                            let mid = parser.remove_http_hdr(&key)
                                .expect("Failed to add header modification");
                            mods.insert(key.clone(), mid.clone());
                            mid
                        }
                    })
                    .collect::<Vec<_>>();

                
                Some(remove)
            })
            .unwrap_or_default();

            debug!("req filter {}: {} patterns, {} modifications", fid, filter.patterns.len(), mids.len());

            filters.push(Filter {
                fid,
                num_patterns: filter.patterns.len(),
                mods: mids
            });

            // next we add the response filter
            // it is only added if the response needs to be modified
            let res = filter.mods
                .clone()
                .and_then(|h| h.response);

            if let Some(res) = res {
                let fid = num_filters + 1;
                parser.start_new_filter(fid as u8);
                num_filters += 1;

                let remove = res.remove.unwrap_or_default()
                    .iter()
                    .map(|key| {
                        // only add a modification once to the dfa
                        if let Some(mid) = mods.get(key) {
                            *mid
                        }
                        else {
                            let mid = parser.remove_http_hdr(&key)
                                .expect("Failed to add header modification");
                            mods.insert(key.clone(), mid.clone());
                            mid
                        }
                    })
                    .collect::<Vec<_>>();

                let mids = remove;
    
                debug!("res filter {}: {} modifications", fid, mids.len());
    
                filters.push(Filter {
                    fid,
                    num_patterns: 0,
                    mods: mids
                });
            }
        }

        // this is necessary so that the DFA won't
        // parse beyond the HTTP header
        parser.done_on_http_hdr_end()?;

        Ok(Self {
            address: address.parse()?,
            config,
            parser,
            filters,
            upstreams: Vec::new(),
            downstreams: Vec::new(),
        })
    }

    pub async fn listen(&mut self) -> Result<()> {
        info!("Listening on {}", self.address);

        let listener = TcpListener::bind(&self.address).await?;
        loop {
            self.accept(&listener).await?;
        }
    }

    async fn accept(&mut self, listener: &TcpListener) -> Result<()> {
        let (downstream, downstream_addr) = listener.accept().await?;
        debug!("Accepted connection on port {:?}", downstream_addr.port());

        let mods = self.parser.modifications.clone();

        let upstream_addrs = self.config.spec.http
            .clone()
            .iter()
            .map(|filter| {
                let dest = &filter.route.first().unwrap().destination;
                self.get_socket_addr_for_dest(dest)
            })
            .collect::<Vec<_>>();

        let mut upstream_sockets = Vec::new();
        for addr in upstream_addrs {
            let socket = TcpStream::connect(addr).await?;
            upstream_sockets.push(socket);
        }

        let mut sm = [[0u32; 256]; 100];
        let mut acts = [[Action::None; 256]; 100];
    
        for (from, to, c, act) in self.parser.iter_transitions() {
            acts[*from as usize][*c as usize] = *act;
            sm[*from as usize][*c as usize] = *to as u32;
        }

        let filters = self.filters.clone();

        tokio::spawn(async move {
            let mut mod_downstream = Modifier::new(downstream, |buf: &mut Vec<u8>| {
                let str = str::from_utf8(buf);
                if str.is_err() {
                    error!("Failed to decode request.");
                    return;
                }

                let mut str = str.unwrap().to_string();
                let mut caps = [(0usize, 0usize); 16];
                let mut cids = [0usize; 16];
                let mut fid_cnt = [0usize; 16];
                let mut s = S_INIT;

                for (i, c) in str.chars().enumerate() {
                    let mut action = acts[s as usize][c as usize];
                    let mut ns = sm[s as usize][c as usize];
                    if ns == 0 {
                        ns = sm[s as usize]['*' as usize];
                        action = acts[s as usize]['*' as usize];
                        if ns == 0 {
                            ns = S_ANY;
                            action = Action::None;
                        }
                    }
                    s = ns;
    
                    match action {
                        Action::StartCapture(cid) => {
                            cids[cid as usize] = i;
                        }
                        Action::EndCapture(cid, mid) => {
                            caps[mid as usize] = (cids[cid as usize], i - cids[cid as usize] + 1);
                        }
                        Action::Match(mid) => {
                            fid_cnt[mid as usize] += 1;
                        }
                        Action::Done => {
                            debug!("Done matching.");
                            break;
                        },
                        Action::None => ()
                    }
                }

                // check if we have a match
                let filter = filters.iter()
                    .find(|f| fid_cnt[f.fid] == f.num_patterns)
                    .cloned();

                if let Some(filter) = filter {
                    debug!("Matched packet.");

                    let mut off: i32 = 0;
                    // for mid in filter.mods {
                    //     let replacement = mods.get(&mid).map(|m| m.replacement.as_str()).unwrap_or_default();
                    //     let tail = mods.get(&mid).map(|m| m.tail).unwrap_or(0);
                    //     let range = caps[mid as usize];
                    //     let range = ((range.0 as i32) + off) as usize .. ((range.1 as i32) + off) as usize - tail as usize;

                    //     debug!("Replacing {:?} with {:?}, diff: {:?}", &str[range.clone()], replacement, replacement.len() as i32 - range.len() as i32);
                    //     off += replacement.len() as i32 - range.len() as i32;

                    //     str.replace_range(range, replacement);
                    // }

                    *buf = str.as_bytes().to_vec();
                }
            });

            let mut upstream = upstream_sockets.iter_mut()
                .next()
                .unwrap();

            // if let Err(e) = copy(&mut mod_downstream, &mut upstream).await {
            //     error!("Error copying req: {:?}", e);
            // }

            // if let Err(e) = copy(&mut upstream, &mut mod_downstream).await {
            //     error!("Error copying res: {:?}", e);
            // }
        });

        Ok(())
    }

    fn get_socket_addr_for_dest(&self, dest: &Destination) -> SocketAddr {
        let host = self.config.hosts.iter()
            .find(|h| h.name == dest.host)
            .expect(format!("Host not found: {}", dest.host).as_str());

        let addr = format!("{}:{}", host.address, dest.port);
        addr.parse()
            .expect(format!("Invalid address: {}", addr).as_str())
    }

}