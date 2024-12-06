use anyhow::{anyhow, Result};
use crate::{config::Host, Config};
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use rand::{distributions::Alphanumeric, Rng};
use sha2::Sha256;
use core::str;
use std::{collections::HashMap, vec};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, time::*};

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(10);

pub fn config() -> Config {
    Config {
        hosts: vec![
            Host {
                name: "server1".into(),
                instances: vec!["127.0.0.1:8001".into()]
            },
            Host {
                name: "server2".into(),
                instances: vec!["127.0.0.1:8002".into()]
            }
        ],
        ..Config::default()
    }
}

fn http_req_from(hdrs: &HashMap<&str, &str>, payload_len: usize) -> String {
    let req = format!("POST / HTTP/1.1\r\n\
                       Host: 127.0.0.1\r\n\
                       Content-Length: {}\r\n", payload_len);
    let mut req = String::from(req); 

    for (k, v) in hdrs {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }

    req.push_str("\r\n");

    let payload = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(payload_len)
        .collect::<Vec<_>>();
    let payload = String::from_utf8(payload).unwrap();
    req.push_str(&payload);

    req
}

fn generate_jwt(secret: &str) -> Result<String> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(secret.as_bytes())?;
    let mut claims = HashMap::new();
    claims.insert("sub", "someone");
    let token = claims.sign_with_key(&key)?;
    Ok(token)
}

async fn write(client: &mut TcpStream, hdrs: &HashMap<&str, &str>) -> Result<String> {
    let req_sent = http_req_from(hdrs, 128);
    let write = client.write_all(req_sent.as_bytes());
    timeout(DEFAULT_TIMEOUT, write).await??;

    Ok(req_sent)
}

async fn try_accept(server: TcpListener) -> Result<TcpStream> {
    let (server, _) = timeout(DEFAULT_TIMEOUT, server.accept()).await??;
    Ok(server)
}

async fn read(server: &mut TcpStream) -> Result<String> {
    let mut req_recv = vec![0; 1024];

    let mut len = 0;
    for _ in 0..10 {
        let readable = server.readable();
        timeout(DEFAULT_TIMEOUT, readable).await??;

        len += server.read(&mut req_recv[len..]).await?;

        match parse_http_hdrs(&req_recv) {
            Ok(_) => break,
            Err(_) => {}
        }
    }

    let req_recv = String::from_utf8(req_recv[..len].to_vec())?;
    Ok(req_recv)
}

async fn write_accept_read(client: &mut TcpStream, server: TcpListener, hdrs: &HashMap<&str, &str>) -> Result<(TcpStream, String, String)> {
    let req_sent = write(client, hdrs).await?;
    let mut server = try_accept(server).await?;
    let req_recv = read(&mut server).await?;

    Ok((server, req_sent, req_recv))
}

fn parse_http_hdrs(buf: &[u8]) -> Result<HashMap<String, String>> {
    if buf.len() == 0 {
        return Err(anyhow!("empty buffer"));
    }

    let mut req_hdr = [httparse::EMPTY_HEADER; 64];
    let mut req = httparse::Request::new(&mut req_hdr);
    req.parse(buf)?;

    let hdrs = req.headers.iter()
        .map(|hdr| {
            let key = hdr.name.to_lowercase();
            let val = String::from_utf8(hdr.value.to_vec()).unwrap();
            (key, val)
        })
        .collect();

    Ok(hdrs)
}

fn assert_http_hdr_eq(buf: &str, exp_hdrs: &HashMap<String, String>) {
    let hdrs = parse_http_hdrs(buf.as_bytes());
    assert!(hdrs.is_ok(), "failed to parse headers: {:?}", hdrs.err().unwrap());

    for (key, val) in hdrs.unwrap().into_iter() {
        let hdr_val = exp_hdrs.get(&key);
        assert!(hdr_val.is_some(), "unexpected header: {:?}", key);

        let exp_val = hdr_val.unwrap();
        assert_eq!(val, *exp_val, "expected {}: {}, got {}", key, exp_val, val);
    }
}

fn assert_http_payload_eq(lhs: &str, rhs: &str) {
    let lhs = lhs.split("\r\n\r\n").collect::<Vec<_>>();
    let rhs = rhs.split("\r\n\r\n").collect::<Vec<_>>();
    assert_eq!(lhs.last().unwrap(), rhs.last().unwrap());
}

async fn setup() -> (TcpListener, TcpListener) {
    _ = env_logger::try_init();

    let mut port = 8001;
    let server1 = loop {
        match TcpListener::bind(format!("127.0.0.1:{port}")).await {
            Ok(server) => break server,
            Err(_) => port += 1
        }
    };

    let server2 = loop {
        match TcpListener::bind(format!("127.0.0.1:{port}")).await {
            Ok(server) => break server,
            Err(_) => port += 1
        }
    };

    (server1, server2)
}

pub async fn it_drops_invalid_jwt(mut client: TcpStream) {
    let (server1, server2) = setup().await;

    let token = generate_jwt("invalid_secret").unwrap();
    let token = format!("Bearer {token}");
    let hdrs = HashMap::from([
        ("backend", "server1"),
        ("Authorization", token.as_str())
    ]);

    let res = write(&mut client, &hdrs).await;
    assert!(res.is_ok());

    let server1_req_recv = try_accept(server1).await;
    assert!(server1_req_recv.is_err());

    let server2_req_recv = try_accept(server2).await;
    assert!(server2_req_recv.is_err());
}

pub async fn it_forwards_valid_jwt(mut client: TcpStream) {
    let (server1, server2) = setup().await;

    let token = generate_jwt("testtest12345678").unwrap();
    let token = format!("Bearer {token}");
    let hdrs = HashMap::from([
        ("backend", "server1"),
        ("authorization", token.as_str())
    ]);

    let (mut server1, req_sent, req_recv) = write_accept_read(&mut client, server1, &hdrs).await.unwrap();
    let mut hdrs_sent = parse_http_hdrs(req_sent.as_bytes()).unwrap();    
    let conn_id = client.local_addr().unwrap().port().to_string();
    hdrs_sent.insert(String::from("conn-id"), conn_id);
    assert_http_hdr_eq(&req_recv, &hdrs_sent);
    assert_http_payload_eq(&req_sent, &req_recv);

    // pipelined HTTP: writing another request without waiting for the response
    let req_sent = write(&mut client, &hdrs).await.unwrap();
    let req_recv = read(&mut server1).await.unwrap();
    assert_http_hdr_eq(&req_recv, &hdrs_sent);
    assert_http_payload_eq(&req_sent, &req_recv);

    let server2_req_recv = try_accept(server2).await;
    assert!(server2_req_recv.is_err());
}