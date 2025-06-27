use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use clap::Parser;
use log::{debug, error};
use reqwest::Client;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    str::FromStr,
};
use tracing_subscriber::field::debug;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:8000")]
    address: String,

    #[arg(short, long)]
    proxy: Option<String>,

    #[arg(short, long)]
    service: String,

    #[arg(short = 'c', long, default_value = "1")]
    service_chain: usize,
}

fn service_addr(base: SocketAddrV4, chain_idx: usize) -> SocketAddrV4 {
    if base.ip().is_loopback() {
        return SocketAddrV4::new(base.ip().clone(), base.port() + chain_idx as u16);
    }

    let [a, b, c, mut d] = base.ip().octets();
    d += chain_idx as u8;

    let ip = Ipv4Addr::new(a, b, c, d);
    SocketAddrV4::new(ip, base.port())
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let Args {
        address,
        proxy,
        service,
        service_chain,
    } = Args::parse();

    let service =
        SocketAddrV4::from_str(service.as_str()).expect("Failed to parse service address");
    let client = Client::new();

    let app = Router::new().route(
        "/",
        post(
            async move |req_hdrs: HeaderMap, body: Bytes| -> Result<String, StatusCode> {
                log::debug!("Received request: {:?}", req_hdrs);

                if let Ok(body) = String::from_utf8(body.to_vec()) {
                    for i in 0..service_chain {
                        let addr = if let Some(proxy) = &proxy {
                            format!("http://{}/service{}", proxy, i)
                        } else {
                            let addr = service_addr(service, i);
                            format!("http://{}/", addr)
                        };

                        debug!("Sending request {} to {}", i, addr);

                        if let Err(e) = client.post(addr.clone()).body(body.clone()).send().await {
                            error!("Error while sending request to {}: {}", addr, e);
                            return Err(StatusCode::BAD_REQUEST);
                        }
                    }

                    return Ok(body);
                }

                Err(StatusCode::BAD_REQUEST)
            },
        ),
    );

    let listener = tokio::net::TcpListener::bind(address.clone())
        .await
        .unwrap();
    log::info!(
        "Listening on {}, chain with {} services",
        address,
        service_chain
    );

    axum::serve(listener, app).await.unwrap();
}
