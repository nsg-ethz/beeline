use std::{convert::Infallible, net::ToSocketAddrs};

use clap::Parser;
use hyper::header::HeaderValue;
use hyper::{body::Body, server::conn::http1};
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper::{
    body::Incoming,
    Request,
    Response
};
use tokio::net::TcpListener;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value="localhost")]
    address: String,
    #[arg(short, long, default_value="8000")]
    port: u16,
    #[arg(short='H', long="header")]
    headers: Option<Vec<String>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Args {
        address,
        port,
        headers
    } = Args::parse();
    let addr = format!("{}:{}", address, port)
        .to_socket_addrs()?
        .next()
        .unwrap();

    println!("Listening on {addr}");

    let listener = TcpListener::bind(addr).await?;

    // We start a loop to continuously accept incoming connections
    loop {
        let (stream, _) = listener.accept().await?;

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
                    let len = req.headers().get("Content-Length")
                        .map(|v| v.clone())
                        .or(HeaderValue::from_str("0").ok())
                        .unwrap();

                    let mut res = Response::builder()
                        .header("Content-Length", len);

                    if let Some(headers) = &headers {
                        for header in headers {
                            let hs: Vec<&str> = header
                                .split_terminator(":")
                                .map(|s| s.trim())
                                .collect();
                            res = res.header(hs[0], hs[1]);
                        }   
                    }

                    res.body(req.into_body())
                }))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}