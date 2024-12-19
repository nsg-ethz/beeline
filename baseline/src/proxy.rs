use crate::pipeline::{Destination, Pipeline};
use anyhow::{anyhow, Result};
use common::Config;
use log::{debug, error, info};
use std::{
    collections::HashMap,
    io::Cursor,
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::RwLock,
};

mod pipeline;

type SocketHashMap = Arc<RwLock<HashMap<SocketAddr, TcpStream>>>;

fn try_split(stream: TcpStream) -> Result<(TcpStream, TcpStream)> {
    let rx = stream.into_std()?;
    let tx = std::net::TcpStream::try_clone(&rx)?;

    Ok((TcpStream::from_std(rx)?, TcpStream::from_std(tx)?))
}

pub struct Proxy {
    pub address: SocketAddr,
    pipeline: Arc<Pipeline>,
    sockets: SocketHashMap,
}

unsafe impl Send for Proxy {}

unsafe impl Sync for Proxy {}

impl Proxy {
    pub fn new<A: ToSocketAddrs>(address: A, config: Config) -> Result<Self> {
        let address = address
            .to_socket_addrs()?
            .next()
            .expect("Failed to resolve address");

        Ok(Proxy {
            address,
            pipeline: Arc::new(Pipeline::new(config)),
            sockets: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    pub async fn listen(self) -> Result<()> {
        let addr = self.address;
        info!("Listening on {}", addr);

        self.pipeline.start_updating_fib(Duration::from_millis(1));

        let listener = TcpListener::bind(&addr).await?;
        loop {
            self.accept(&listener).await?;
        }
    }

    async fn accept(&self, listener: &TcpListener) -> Result<()> {
        let (downstream, downstream_addr) = listener.accept().await?;
        debug!("Accepted connection on port {:?}", downstream_addr.port());

        let (rx, tx) = try_split(downstream)?;

        self.sockets.write().await.insert(downstream_addr, tx);

        if let Err(e) = Self::start_reading(rx, true, self.pipeline.clone(), self.sockets.clone()) {
            error!("Error handling connection: {:?}", e);
        }

        Ok(())
    }

    fn start_reading(
        stream: TcpStream,
        is_downstream: bool,
        pipeline: Arc<Pipeline>,
        sockets: SocketHashMap,
    ) -> Result<()> {
        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(8192);
            let res: Result<(), _> = loop {
                match stream.readable().await {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(()) => {}
                }

                let buf_len = match stream.try_read_buf(&mut buf) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(0) => break Ok(()),
                    Ok(len) => len,
                };

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
                if buf_len < req_len {
                    debug!("Request not fully read: {buf_len}/{req_len}");
                    continue;
                }

                let origin = if is_downstream {
                    stream.peer_addr().unwrap()
                } else {
                    stream.local_addr().unwrap()
                };

                let mut msg = buf.drain(..req_len).collect();
                let dest = match pipeline.process(&mut msg, origin, is_downstream).await {
                    Ok(dest) => dest,
                    Err(e) => break Err(e),
                };

                let addr = match dest {
                    Destination::Exisiting(addr) => addr,
                    Destination::New(addr, ft) => {
                        debug!(
                            "Opening upstream connection [{}->{}]",
                            stream.local_addr().unwrap(),
                            addr
                        );

                        let upstream = match TcpStream::connect(addr).await {
                            Ok(upstream) => upstream,
                            Err(e) => break Err(anyhow!(e)),
                        };
                        let addr = upstream.local_addr().unwrap();
                        let (rx, tx) = try_split(upstream).unwrap();

                        sockets.write().await.insert(addr, tx);
                        pipeline.add_sock(ft, addr).await;

                        Self::start_reading(rx, false, pipeline.clone(), sockets.clone()).unwrap();

                        addr
                    }
                };

                debug!("Forward msg {} -> {}", origin, addr);

                let mut sockets_wr = sockets.write().await;
                let wr_stream = sockets_wr.get_mut(&addr).unwrap();
                let mut req_buf = Cursor::new(&msg);
                wr_stream.write_all_buf(&mut req_buf).await.unwrap();
            };

            if let Err(e) = res {
                error!("Error handling connection: {:?}", e);
            } else {
                debug!("Connection closed: {}", stream.peer_addr().unwrap());
            }
        });

        Ok(())
    }
}
