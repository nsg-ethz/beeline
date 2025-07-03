use std::{collections::HashMap, str::FromStr};

use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    routing::post,
};
use clap::Parser;
use log::{debug, error};
use reqwest::Client;
use tokio::{
    signal::unix::{SignalKind, signal},
    task::JoinSet,
};

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:8000")]
    address: String,

    #[arg(short = 'H', long = "header")]
    headers: Option<Vec<String>>,

    #[arg(short, long)]
    proxy: Option<String>,

    #[arg(short, long, default_value = "echo")]
    service_prefix: String,

    #[arg(short = 'n', long, default_value = "1")]
    num_services: usize,

    #[arg(short, long, default_value = "false")]
    fan_out: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let Args {
        address,
        headers,
        proxy,
        service_prefix,
        num_services,
        fan_out,
    } = Args::parse();

    let client = Client::new();
    let headers = headers
        .unwrap_or(vec![])
        .iter()
        .map(|h| {
            let hs: Vec<&str> = h.split_terminator(":").map(|s| s.trim()).collect();
            let key = HeaderName::from_str(hs[0]).expect("Invalid header key");
            let val = HeaderValue::from_str(hs[1]).expect("Invalid header value");
            (key, val)
        })
        .collect::<HeaderMap<HeaderValue>>();

    let strategy_msg = if fan_out { "fan-out" } else { "chain" };
    let proxy_msg = if let Some(proxy) = &proxy {
        format!("connecting via proxy ({})", proxy)
    } else {
        "connecting directly".to_string()
    };
    log::info!(
        "Listening on {}, {} with {} services, {}",
        address,
        strategy_msg,
        num_services,
        proxy_msg
    );
    if headers.len() > 0 {
        log::info!("Will use headers: {:?}", headers);
    }

    let svc = if fan_out {
        post(
            async move |req_hdrs: HeaderMap, body: Bytes| -> Result<String, StatusCode> {
                log::debug!("Received request: {:?}", req_hdrs);

                if let Ok(body) = String::from_utf8(body.to_vec()) {
                    let mut set = JoinSet::new();
                    for i in 1..=num_services {
                        let addr = if let Some(proxy) = &proxy {
                            format!("http://{}/{}{}", proxy, service_prefix, i)
                        } else {
                            format!("http://{}{}/", service_prefix, i)
                        };

                        debug!("Sending request {} to {}", i, addr);

                        set.spawn(
                            client
                                .post(addr.clone())
                                .headers(headers.clone())
                                .body(body.clone())
                                .send(),
                        );
                    }

                    while let Some(res) = set.join_next().await {
                        let res = match res {
                            Ok(res) => res,
                            Err(err) => {
                                error!("Request failed: {:?}", err);
                                return Err(StatusCode::BAD_REQUEST);
                            }
                        };

                        if let Err(e) = handle_echo_res(res).await {
                            return Err(e);
                        }
                    }

                    return Ok(body);
                }

                Err(StatusCode::BAD_REQUEST)
            },
        )
    } else {
        post(
            async move |req_hdrs: HeaderMap, body: Bytes| -> Result<String, StatusCode> {
                log::debug!("Received request: {:?}", req_hdrs);

                if let Ok(body) = String::from_utf8(body.to_vec()) {
                    for i in 1..=num_services {
                        let addr = if let Some(proxy) = &proxy {
                            format!("http://{}/{}{}", proxy, service_prefix, i)
                        } else {
                            format!("http://{}{}/", service_prefix, i)
                        };

                        debug!("Sending request {} to {}", i, addr);

                        let res = client
                            .post(addr.clone())
                            .headers(headers.clone())
                            .body(body.clone())
                            .send()
                            .await;
                        if let Err(e) = handle_echo_res(res).await {
                            return Err(e);
                        }
                    }

                    return Ok(body);
                }

                Err(StatusCode::BAD_REQUEST)
            },
        )
    };

    let app = Router::new().route("/", svc);

    let listener = tokio::net::TcpListener::bind(address.clone())
        .await
        .unwrap();

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

async fn handle_echo_res(res: reqwest::Result<reqwest::Response>) -> Result<(), StatusCode> {
    match res {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                let response_body = response.text().await.unwrap();
                log::trace!("Received response: {}", response_body);
                Ok(())
            } else {
                let response_body = response.text().await.unwrap();
                error!("Request failed: {:?} {:?}", status, response_body);
                Err(StatusCode::BAD_REQUEST)
            }
        }
        Err(e) => {
            error!("Error while sending request: {:?}", e);
            Err(StatusCode::BAD_REQUEST)
        }
    }
}
