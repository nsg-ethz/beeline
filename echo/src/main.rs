use anyhow::Result;
use clap::Parser;
use core::str;
use hyper::server::conn::http1::Builder;
use hyper::{body::Incoming, service::service_fn, Response};
use hyper_util::rt::TokioIo;
use log::{debug, error, info};
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpSocket;
use tokio::{
    net::{TcpListener, TcpStream},
    runtime::{Builder as RuntimeBuilder, Handle},
};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:8000")]
    address: String,

    #[arg(short = 'H', long = "header")]
    headers: Option<Vec<String>>,

    #[arg(short = 'e', long = "echo-header")]
    header_echos: Option<Vec<String>>,

    #[arg(short = 'd', long = "us-delay", default_value = "0")]
    delay_us: u64,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let Args {
        address,
        headers,
        header_echos,
        delay_us,
    } = Args::parse();
    let addr = address.parse()?;

    run(addr, move |socket, http, handle| {
        let headers = headers.clone();
        let header_echos = header_echos.clone();

        let svc = service_fn(move |req| {
            let headers = headers.clone();
            let header_echos = header_echos.clone();

            async move {
                debug!("Received request: {:?}", req);

                // this helps simulating slower backends
                if delay_us > 0 {
                    std::thread::sleep(Duration::from_micros(delay_us));
                }

                let mut res = Response::builder();
                if let Some(headers) = &headers {
                    for header in headers {
                        let hs: Vec<&str> =
                            header.split_terminator(":").map(|s| s.trim()).collect();
                        res = res.header(hs[0], hs[1]);
                    }
                }
                if let Some(header_echos) = &header_echos {
                    for key in header_echos {
                        if let Some(val) = req.headers().get(key) {
                            res = res.header(key, val);
                        }
                    }
                }

                let body: Incoming = req.into_body();
                res.body(body)
            }
        });

        let io = TokioIo::new(socket);
        let conn = http.serve_connection(io, svc);
        handle.spawn(async move {
            conn.await.inspect_err(|e| {
                error!("Connection failed: {e}");
            })
        });
    });

    Ok(())
}

fn run<F>(addr: SocketAddr, per_connection: F)
where
    F: Fn(TcpStream, &mut Builder, Handle) + Clone + Send + 'static,
{
    info!("Listening on {addr}");

    let mut http = Builder::new();
    let core = RuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let handle = core.handle();

    // For every accepted connection, spawn an HTTP task
    let server = async move {
        let tcp = reuse_listener(&addr).expect("Failed to bind to address");
        loop {
            match tcp.accept().await {
                Ok((sock, _)) => {
                    debug!("Accepted connection {:?}", sock.peer_addr().unwrap());
                    let _ = sock.set_nodelay(true);
                    per_connection(sock, &mut http, handle.clone());
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e)
                }
            }
        }
    };

    core.block_on(server);
}

fn reuse_listener(addr: &SocketAddr) -> Result<TcpListener> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseport(true)?;
    socket.set_reuseaddr(true)?;
    socket.bind(*addr)?;

    let listener = socket.listen(1024)?;
    Ok(listener)
}
