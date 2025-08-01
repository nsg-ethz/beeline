use crate::pipeline::{Destination, Pipeline};
use anyhow::{anyhow, Result};
use common::config::beeline::Config;
use futures::{
    stream::{FuturesUnordered, StreamExt},
    TryFutureExt,
};
use log::{debug, error, info, trace};
use std::{
    collections::{HashMap, VecDeque},
    io::Cursor,
    net::{SocketAddr, ToSocketAddrs},
    os::fd::AsRawFd,
    process::exit,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    signal::unix::{signal, SignalKind},
};

mod pipeline;
mod stats;

pub struct Proxy {
    pub address: SocketAddr,
    config: Config,
}

unsafe impl Send for Proxy {}

unsafe impl Sync for Proxy {}

impl Proxy {
    pub fn new<A: ToSocketAddrs>(address: A, config: Config) -> Result<Self> {
        let address = address
            .to_socket_addrs()?
            .next()
            .expect("Failed to resolve address");

        Ok(Proxy { address, config })
    }

    pub async fn listen(self) -> Result<()> {
        let socket = TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;
        socket.bind(self.address)?;
        let listener = socket.listen(4096)?;

        info!("Listening on {}", self.address);

        tokio::spawn(async move {
            let mut sigterm = signal(SignalKind::terminate()).unwrap();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }

            stats::print();
            exit(0)
        });

        loop {
            self.accept(&listener).await?;
        }
    }

    async fn accept(&self, listener: &TcpListener) -> Result<()> {
        let (downstream, downstream_addr) = listener.accept().await?;
        debug!("Accepted connection on port {:?}", downstream_addr.port());

        let pipeline = Pipeline::new(self.config.clone(), Duration::from_millis(10));
        if let Err(e) = Self::start_reading(downstream, pipeline) {
            error!("Error handling connection: {:?}", e);
        }

        Ok(())
    }

    fn start_reading(stream: TcpStream, mut pipeline: Pipeline) -> Result<()> {
        let stream_addr = stream.peer_addr()?;
        let stream_fd = stream.as_raw_fd();
        let (rx, tx) = stream.into_split();

        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(8192);
            let mut rxs = VecDeque::new();
            rxs.push_back(rx);

            let mut txs = HashMap::new();
            txs.insert(stream_addr, tx);

            let res: Result<(), _> = loop {
                let mut readable = rxs
                    .iter()
                    .enumerate()
                    .map(|(idx, rx)| rx.readable().map_ok(move |_| idx))
                    .collect::<FuturesUnordered<_>>();

                let rx = match readable.next().await.unwrap() {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(rx) => rx,
                };
                let rx = rxs.get(rx).unwrap();
                drop(readable);

                match rx.try_read_buf(&mut buf) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(0) => break Ok(()),
                    Ok(len) => len,
                };

                let start_parse = Instant::now();

                let is_downstream = rx.as_ref().as_raw_fd() == stream_fd;
                let mut headers = [httparse::EMPTY_HEADER; 64];
                let (hdr_len, hdrs) = if is_downstream {
                    let mut req = httparse::Request::new(&mut headers);
                    let hdr_len = req.parse(&buf);
                    if let Err(e) = hdr_len {
                        break Err(anyhow!(e));
                    }

                    (hdr_len, req.headers)
                } else {
                    let mut req = httparse::Response::new(&mut headers);
                    let hdr_len = req.parse(&buf);
                    if let Err(e) = hdr_len {
                        break Err(anyhow!(e));
                    }

                    (hdr_len, req.headers)
                };

                let parse_duration = start_parse.elapsed().as_nanos();
                stats::PARSE_TOTAL.fetch_add(parse_duration as u64, Ordering::Relaxed);
                stats::PARSE_COUNT.fetch_add(1, Ordering::Relaxed);

                let start_other = Instant::now();

                let con_len = hdrs
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);

                let hdr_len = match hdr_len.unwrap() {
                    httparse::Status::Complete(len) => len,
                    httparse::Status::Partial => continue,
                };

                let req_len = hdr_len + con_len;
                if buf.len() < req_len {
                    debug!("Request not fully read: {}/{}", buf.len(), req_len);
                    continue;
                }

                let origin = if is_downstream {
                    rx.peer_addr().unwrap()
                } else {
                    rx.local_addr().unwrap()
                };

                let mut msg = buf.drain(..req_len).collect();
                let dest = match pipeline.process(&mut msg, origin, is_downstream) {
                    Ok(dest) => dest,
                    Err(e) => break Err(e),
                };

                let addr = match dest {
                    Destination::Exisiting(addr) => addr,
                    Destination::New(addr, ft) => {
                        debug!("Opening upstream connection [{}->{}]", origin, addr);

                        let upstream = match TcpStream::connect(addr).await {
                            Ok(upstream) => upstream,
                            Err(e) => break Err(anyhow!(e)),
                        };

                        let addr = upstream.local_addr().unwrap();
                        let (rx, tx) = upstream.into_split();

                        rxs.push_back(rx);
                        txs.insert(addr, tx);
                        pipeline.add_sock(ft, addr);

                        addr
                    }
                };

                let other_duration = start_other.elapsed().as_nanos();
                stats::OTHER_TOTAL.fetch_add(other_duration as u64, Ordering::Relaxed);
                stats::OTHER_COUNT.fetch_add(1, Ordering::Relaxed);

                trace!("Forward msg {} -> {}", origin, addr);

                let tx = txs.get_mut(&addr).unwrap();
                let mut req_buf = Cursor::new(&msg);
                tx.write_all_buf(&mut req_buf).await.unwrap();
            };

            if let Err(e) = res {
                error!("Error handling connection: {:?}", e);
            } else {
                debug!("Connection closed: {}", stream_addr);
            }
        });

        Ok(())
    }
}
