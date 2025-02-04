use anyhow::Result;
use axum::{
    body::Bytes,
    http::{HeaderMap, HeaderName, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use clap::Parser;
use std::{collections::HashMap, str::FromStr, time::Duration};

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

    // build our application with a route
    let app = Router::new().route(
        "/",
        post(move |req_hdrs: HeaderMap, body: Bytes| {
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
        }),
    );

    // run our app with hyper, listening globally on port 3000
    let listener = tokio::net::TcpListener::bind(address).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn echo(headers: HeaderMap, body: Bytes) -> Result<impl IntoResponse, StatusCode> {
    if let Ok(body) = String::from_utf8(body.to_vec()) {
        Ok((headers, body))
    } else {
        Err(StatusCode::BAD_REQUEST)
    }
}
