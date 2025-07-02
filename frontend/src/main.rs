use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use clap::Parser;
use log::{debug, error};
use reqwest::Client;
use tokio::signal::unix::{SignalKind, signal};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:8000")]
    address: String,

    #[arg(short, long)]
    proxy: Option<String>,

    #[arg(short, long, default_value = "echo")]
    service_prefix: String,

    #[arg(short = 'c', long, default_value = "1")]
    service_chain: usize,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let Args {
        address,
        proxy,
        service_prefix,
        service_chain,
    } = Args::parse();

    let client = Client::new();

    let app = Router::new().route(
        "/",
        post(
            async move |req_hdrs: HeaderMap, body: Bytes| -> Result<String, StatusCode> {
                log::debug!("Received request: {:?}", req_hdrs);

                if let Ok(body) = String::from_utf8(body.to_vec()) {
                    for i in 0..service_chain {
                        let addr = if let Some(proxy) = &proxy {
                            format!("http://{}/{}{}", proxy, service_prefix, i)
                        } else {
                            format!("http://{}{}/", service_prefix, i)
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

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .unwrap();
}

async fn shutdown_signal() {
    let mut sigterm = signal(SignalKind::terminate()).unwrap();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = sigterm.recv() => {},
    }
}
