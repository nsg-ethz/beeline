use anyhow::Result;
use core::str;
use clap::Parser;
use hyper::{
    body::Incoming,
    Request,
    Response,
    server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use log::{debug, info, error};
use std::{os::fd::AsFd, time::Duration};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpSocket;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value="127.0.0.1:8000")]
    address: String,

    #[arg(short='H', long="header")]
    headers: Option<Vec<String>>,
}

fn prepare_socket<S: AsFd>(socket: &S) -> Result<()> {
    let socket = SockRef::from(&socket);
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(10));

    socket.set_nodelay(true)?;
    socket.set_tcp_keepalive(&ka)?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let Args {
        address,
        headers
    } = Args::parse();

    let addr = address.parse()?;

    info!("Listening on {addr}");

    let socket = TcpSocket::new_v4()?;
    socket.set_reuseaddr(true)?;
    prepare_socket(&socket)?;
    socket.bind(addr)?;

    let listener = socket.listen(4096)?;

    // We start a loop to continuously accept incoming connections
    loop {
        let (stream, _) = listener.accept().await?;
        prepare_socket(&stream)?;
        
        debug!("Accepted connection {:?}", stream.peer_addr().unwrap());

        // Use an adapter to access something implementing `tokio::io` traits as if they implement
        // `hyper::rt` IO traits.
        let io = TokioIo::new(stream);
        let headers = headers.clone();

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, we bind the incoming connection to our `hello` service
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(io, service_fn(|req: Request<Incoming>| async {
                    debug!("Received request: {:?}", req);

                    let mut res = Response::builder();

                    if let Some(headers) = &headers {
                        for header in headers {
                            let hs: Vec<&str> = header
                                .split_terminator(":")
                                .map(|s| s.trim())
                                .collect();
                            res = res.header(hs[0], hs[1]);
                        }   
                    }

                    let body: Incoming = req.into_body();
                    res.body(body)
                }))
                .await
            {
                error!("Error serving connection: {:?}", err);
            }
        });
    }
}