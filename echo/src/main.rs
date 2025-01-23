use anyhow::Result;
use clap::Parser;
use core::str;
use hyper::{body::Incoming, service::service_fn, Response};
use hyper_util::rt::TokioIo;
use log::debug;
use std::time::Duration;

mod server;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:8000")]
    address: String,

    #[arg(short = 'H', long = "header")]
    headers: Option<Vec<String>>,

    #[arg(short = 'e', long = "echo-header")]
    header_echos: Option<Vec<String>>,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    env_logger::init();

    let Args {
        address,
        headers,
        header_echos,
    } = Args::parse();
    let addr = address.parse()?;

    server::run(addr, move |socket, http, handle| {
        let headers = headers.clone();
        let header_echos = header_echos.clone();

        let svc = service_fn(move |req| {
            let headers = headers.clone();
            let header_echos = header_echos.clone();

            async move {
                debug!("Received request: {:?}", req);

                // this delay is necessary to make the server compute bound rather than IO bound
                std::thread::sleep(Duration::from_micros(500));

                let mut res = Response::builder();
                if let Some(headers) = &headers {
                    for header in headers {
                        let hs: Vec<&str> =
                            header.split_terminator(":").map(|s| s.trim()).collect();
                        res = res.header(hs[0], hs[1]);
                    }
                }
                if let Some(header_echos) = &header_echos {
                    for key in header_echos {
                        if let Some(val) = req.headers().get(key) {
                            res = res.header(key, val);
                        }
                    }
                }

                let body: Incoming = req.into_body();
                res.body(body)
            }
        });

        let io = TokioIo::new(socket);
        handle.spawn(http.serve_connection(io, svc));
    });

    Ok(())
}
