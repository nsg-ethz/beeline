use anyhow::{anyhow, Result};
use crate::pipeline::Pipeline;
use log::{debug, error, info};
use std::{net::{SocketAddr, ToSocketAddrs}, sync::Arc};
use tokio::{io, net::{TcpListener, TcpStream}};

pub struct Proxy {
    pub address: SocketAddr,
    pipeline: Arc<Pipeline>,
}

unsafe impl Send for Proxy {}

unsafe impl Sync for Proxy {}

impl Proxy {

    pub fn new<A: ToSocketAddrs>(address: A) -> Result<Self> {
        let address = address.to_socket_addrs()?
            .next()
            .expect("Failed to resolve address");

        Ok(Proxy {
            address,
            pipeline: Arc::new(Pipeline::new()),
        })
    }

    pub async fn listen(self) -> Result<()> {
        let addr = self.address;
        info!("Listening on {}", addr);

        let listener = TcpListener::bind(&addr).await?;
        loop {
            self.accept(&listener).await?;
        }
    }

    async fn accept(&self, listener: &TcpListener) -> Result<()> {
        let (downstream, downstream_addr) = listener.accept().await?;
        debug!("Accepted connection on port {:?}", downstream_addr.port());

        if let Err(e) = self.handle_downstream(downstream).await {
            error!("Error handling downstream connection: {:?}", e);
        }

        Ok(())
    }

    async fn handle_downstream(&self, downstream: TcpStream) -> Result<()> {
        let pipeline = self.pipeline.clone();

        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(8192);

            let res = loop {
                // wait until the downstream connection is readable
                match downstream.readable().await {
                    Err(ref e)if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(()) => {}
                }

                let buf_len = match downstream.try_read_buf(&mut buf) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(0) => break Ok(()),
                    Ok(len) => len,
                };

                let mut headers = [httparse::EMPTY_HEADER; 8192];
                let mut req = httparse::Request::new(&mut headers);
                let hdr_len = req.parse(&buf);
                if let Err(e) = hdr_len {
                    break Err(anyhow!(e));
                }

                let con_len = req.headers.iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h|  std::str::from_utf8(h.value).ok())
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

                if let Err(e) = pipeline.clone().process(&buf[..req_len], downstream.peer_addr().unwrap()).await {
                    break Err(e);
                }

                buf.clear();
            };

            if let Err(e) = res {
                error!("Error handling downstream connection: {:?}", e);
            }
        });

        Ok(())
    }

}