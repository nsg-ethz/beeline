use crate::stream::SpyStream;
use anyhow::Result;
use axum::{
    body::Bytes,
    http::{HeaderMap, HeaderName, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use clap::Parser;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server;
use std::{collections::HashMap, str::FromStr, time::Duration};
// use tokio::signal::unix::{signal, SignalKind};
use tower::Service;
use tracing::{info, trace};

mod stream;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:8000")]
    address: String,

    #[arg(short = 'H', long = "header")]
    headers: Option<Vec<String>>,

    #[arg(short = 'e', long = "echo-header")]
    header_echos: Option<Vec<String>>,

    #[arg(short = 'd', long = "us-delay", default_value = "0")]
    delay_us: u64,
}

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();

    let Args {
        address,
        headers,
        header_echos,
        delay_us,
    } = Args::parse();

    let headers = headers
        .unwrap_or(vec![])
        .iter()
        .map(|h| {
            let hs: Vec<&str> = h.split_terminator(":").map(|s| s.trim()).collect();
            (hs[0].to_string(), hs[1].to_string())
        })
        .collect::<HashMap<String, String>>();
    let header_echos = header_echos.unwrap_or_default();

    let echo = post(move |req_hdrs: HeaderMap, body: Bytes| {
        trace!("Received request: {:?}", req_hdrs);
        // this helps simulating slower backends
        if delay_us > 0 {
            std::thread::sleep(Duration::from_micros(delay_us));
        }

        let mut res_hdrs = HeaderMap::new();
        for (key, val) in headers.into_iter() {
            let key = HeaderName::from_str(key.as_str()).unwrap();
            res_hdrs.insert(key, val.parse().unwrap());
        }

        req_hdrs
            .iter()
            .filter(|(k, _)| header_echos.contains(&k.to_string()))
            .for_each(|(k, v)| {
                res_hdrs.insert(k, v.clone());
            });

        echo(res_hdrs, body)
    });

    // build our application with a route
    let app = Router::new()
        .route("/", echo.clone())
        .route("/{path}", echo);

    let listener = tokio::net::TcpListener::bind(address.clone())
        .await
        .unwrap();
    info!("Listening on {}", address);

    // axum::serve(listener, app)
    //     .with_graceful_shutdown(shutdown_signal())
    //     .await
    //     .unwrap();

    loop {
        // In this example we discard the remote address. See `fn serve_with_connect_info` for how
        // to expose that.
        let (socket, _remote_addr) = listener.accept().await.unwrap();

        // We don't need to call `poll_ready` because `Router` is always ready.
        let tower_service = app.clone();

        // Spawn a task to handle the connection. That way we can handle multiple connections
        // concurrently.
        tokio::spawn(async move {
            // Hyper has its own `AsyncRead` and `AsyncWrite` traits and doesn't use tokio.
            // `TokioIo` converts between them.
            let socket = SpyStream(socket);
            let socket = TokioIo::new(socket);

            // Hyper also has its own `Service` trait and doesn't use tower. We can use
            // `hyper::service::service_fn` to create a hyper `Service` that calls our app through
            // `tower::Service::call`.
            let hyper_service = hyper::service::service_fn(
                move |request: axum::extract::Request<hyper::body::Incoming>| {
                    // We have to clone `tower_service` because hyper's `Service` uses `&self` whereas
                    // tower's `Service` requires `&mut self`.
                    //
                    // We don't need to call `poll_ready` since `Router` is always ready.
                    tower_service.clone().call(request)
                },
            );

            // `server::conn::auto::Builder` supports both http1 and http2.
            //
            // `TokioExecutor` tells hyper to use `tokio::spawn` to spawn tasks.
            if let Err(err) = server::conn::auto::Builder::new(TokioExecutor::new())
                // `serve_connection_with_upgrades` is required for websockets. If you don't need
                // that you can use `serve_connection` instead.
                .serve_connection_with_upgrades(socket, hyper_service)
                .await
            {
                eprintln!("failed to serve connection: {err:#}");
            }
        });
    }
}

async fn echo(headers: HeaderMap, body: Bytes) -> Result<impl IntoResponse, StatusCode> {
    if let Ok(body) = String::from_utf8(body.to_vec()) {
        Ok((headers, body))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}

// async fn shutdown_signal() {
//     let mut sigterm = signal(SignalKind::terminate()).unwrap();
//     tokio::select! {
//         _ = tokio::signal::ctrl_c() => {},
//         _ = sigterm.recv() => {},
//     }
// }
