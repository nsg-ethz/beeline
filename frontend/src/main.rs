use axum::{
    Router,
    body::Bytes,
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode},
    routing::post,
};
use clap::Parser;
use reqwest::Client;
use std::str::FromStr;
use tokio::{
    signal::unix::{SignalKind, signal},
    task::JoinSet,
};
use tracing::{debug, error, info, trace};

#[derive(Parser)]
#[command(ignore_errors(true))] // this way we can pass FRONTEND_ARGS, even if it's an empty string
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:8000")]
    address: String,

    #[arg(short = 'H', long = "header")]
    headers: Option<Vec<String>>,

    #[arg(short, long)]
    proxy: Option<String>,

    #[arg(short, long, default_value = "echo")]
    service_prefix: String,

    #[arg(short, long, default_value = "false")]
    fan_out: bool,
}

#[derive(Clone)]
struct HandlerState {
    proxy: Option<String>,
    service_prefix: String,
    client: Client,
    headers: HeaderMap<HeaderValue>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let Args {
        address,
        headers,
        proxy,
        service_prefix,
        fan_out,
    } = Args::parse();

    let client = Client::new();
    let headers = headers
        .unwrap_or(vec![])
        .iter()
        .flat_map(|h| {
            h.split_terminator(",")
                .map(|s| s.trim())
                .collect::<Vec<&str>>()
        })
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
    info!("Listening on {}, {}, {}", address, strategy_msg, proxy_msg);
    if headers.len() > 0 {
        info!("Will use headers: {:?}", headers);
    }

    let state = HandlerState {
        proxy,
        service_prefix,
        client,
        headers,
    };

    let svc = if fan_out {
        post(echo_fan_out)
    } else {
        post(echo_chain)
    };

    let app = Router::new()
        .route("/", svc.clone())
        .route("/echo/{*count}", svc)
        .with_state(state);

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

async fn echo_fan_out(
    State(state): State<HandlerState>,
    Path(num_services): Path<u32>,
    req_hdrs: HeaderMap,
    body: Bytes,
) -> Result<String, StatusCode> {
    debug!("Received request: {:?}", req_hdrs);

    if let Ok(body) = String::from_utf8(body.to_vec()) {
        let mut set = JoinSet::new();
        for i in 1..=num_services {
            let addr = if let Some(proxy) = &state.proxy {
                format!("http://{}/{}{}", proxy, state.service_prefix, i)
            } else {
                format!("http://{}{}/", state.service_prefix, i)
            };

            debug!("Sending request {} to {}", i, addr);

            set.spawn(
                state
                    .client
                    .post(addr.clone())
                    .headers(state.headers.clone())
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
}

async fn echo_chain(
    State(state): State<HandlerState>,
    Path(num_services): Path<u32>,
    req_hdrs: HeaderMap,
    body: Bytes,
) -> Result<String, StatusCode> {
    debug!("Received request: {:?}", req_hdrs);

    if let Ok(body) = String::from_utf8(body.to_vec()) {
        for i in 1..=num_services {
            let addr = if let Some(proxy) = &state.proxy {
                format!("http://{}/{}{}", proxy, state.service_prefix, i)
            } else {
                format!("http://{}{}/", state.service_prefix, i)
            };

            debug!("Sending request {} to {}", i, addr);

            let res = state
                .client
                .post(addr.clone())
                .headers(state.headers.clone())
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
}

async fn handle_echo_res(res: reqwest::Result<reqwest::Response>) -> Result<(), StatusCode> {
    match res {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                let response_body = response.text().await.unwrap();
                trace!("Received response: {}", response_body);
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
