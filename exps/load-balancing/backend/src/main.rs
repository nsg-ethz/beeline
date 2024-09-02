use std::convert::Infallible;
use std::net::ToSocketAddrs;

use clap::Parser;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::Response;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value="localhost")]
    address: String,
    #[arg(short, long, default_value="8000")]
    port: u16,
    #[arg(short, long)]
    name: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Args {
        address,
        port,
        name
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
        let name = name.clone();

        // Spawn a tokio task to serve multiple connections concurrently
        tokio::task::spawn(async move {
            // Finally, we bind the incoming connection to our `hello` service
            if let Err(err) = http1::Builder::new()
                // `service_fn` converts our function in a `Service`
                .serve_connection(io, service_fn(|_| async {
                    let res = format!("Hello from {}", name);
                    Ok(Response::new(Full::<Bytes>::from(res))) as Result<_, Infallible>
                }))
                .await
            {
                println!("Error serving connection: {:?}", err);
            }
        });
    }
}