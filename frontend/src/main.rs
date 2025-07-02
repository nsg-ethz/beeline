use axum::{
    Router,
    body::Bytes,
    http::{HeaderMap, StatusCode},
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

    #[arg(short, long)]
    proxy: Option<String>,

    #[arg(short, long, default_value = "echo")]
    service_prefix: String,

    #[arg(short = 'c', long, default_value = "1")]
    service_chain: usize,

    #[arg(short, long, default_value = "false")]
    fan_out: bool,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let Args {
        address,
        proxy,
        service_prefix,
        service_chain,
        fan_out,
    } = Args::parse();

    let client = Client::new();

    let svc = if fan_out {
        post(
            async move |req_hdrs: HeaderMap, body: Bytes| -> Result<String, StatusCode> {
                log::debug!("Received request: {:?}", req_hdrs);

                if let Ok(body) = String::from_utf8(body.to_vec()) {
                    let mut set = JoinSet::new();
                    for i in 1..=service_chain {
                        let addr = if let Some(proxy) = &proxy {
                            format!("http://{}/{}{}", proxy, service_prefix, i)
                        } else {
                            format!("http://{}{}/", service_prefix, i)
                        };

                        debug!("Sending request {} to {}", i, addr);

                        set.spawn(client.post(addr.clone()).body(body.clone()).send());
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
                    for i in 1..=service_chain {
                        let addr = if let Some(proxy) = &proxy {
                            format!("http://{}/{}{}", proxy, service_prefix, i)
                        } else {
                            format!("http://{}{}/", service_prefix, i)
                        };

                        debug!("Sending request {} to {}", i, addr);

                        let res = client.post(addr.clone()).body(body.clone()).send().await;
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

    let strategy = if fan_out { "fan-out" } else { "chain" };
    log::info!(
        "Listening on {}, {} with {} services",
        address,
        strategy,
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
