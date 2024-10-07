use std::collections::HashMap;

use log::{debug, info};
use tonic::{transport::Server, Request, Response, Status};
use echo::{
    EchoReply, 
    EchoRequest,
    echo_server::{Echo, EchoServer},
};

pub mod echo {
    tonic::include_proto!("echo"); // The string specified here must match the proto package name
}

#[derive(Debug, Default)]
pub struct EchoService {
    signature: String,
}

#[tonic::async_trait]
impl Echo for EchoService {

    async fn send(&self, request: Request<EchoRequest>) -> Result<Response<EchoReply>, Status> {
        debug!("Received request: {:?}", request);

        let reply = EchoReply {
            signature: self.signature.clone(),
            payload: request.into_inner().payload
        };

        Ok(Response::new(reply)) // Send back our formatted greeting
    }
}

pub async fn listen(addr: String, meta_data: Vec<String>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addr = addr.parse()?;
    info!("Listening for RPC on {addr}");

    let meta_data = meta_data.iter()
        .map(|s| {
            let vals: Vec<&str> = s
                            .split_terminator(":")
                            .map(|s| s.trim())
                            .collect();
            (vals[0].to_string(), vals[1].to_string())
        })
        .collect::<HashMap<String, String>>();

    if !meta_data.contains_key("signature") {
        return Err("signature not found in metadata".into());
    }
    let signature = meta_data.get("signature")
        .unwrap()
        .clone();

    let echo = EchoService {
        signature,
    };
    let server = EchoServer::new(echo);

    Server::builder()
        .add_service(server)
        .serve(addr)
        .await?;

    Ok(())
}