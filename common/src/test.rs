use anyhow::{anyhow, Result};
use crate::{config::Host, Config};
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use rand::{distributions::Alphanumeric, Rng};
use sha2::Sha256;
use core::str;
use std::{collections::HashMap, vec};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, time::{self, *}};

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

fn http_msg_from(hdrs: &HashMap<&str, &str>, payload_len: usize, is_req: bool) -> String {
    let msg = if is_req {
        format!("POST / HTTP/1.1\r\n\
                Host: 127.0.0.1\r\n\
                Content-Length: {}\r\n", payload_len)
    }
    else {
        format!("HTTP/1.1 200 OK\r\n\
                Host: 127.0.0.1\r\n\
                Content-Length: {}\r\n", payload_len)
    };
    let mut msg = String::from(msg); 

    for (k, v) in hdrs {
        msg.push_str(&format!("{}: {}\r\n", k, v));
    }

    msg.push_str("\r\n");

    let payload = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(payload_len)
        .collect::<Vec<_>>();
    let payload = String::from_utf8(payload).unwrap();
    msg.push_str(&payload);

    msg
}

fn generate_jwt(secret: &str) -> Result<String> {
    let key: Hmac<Sha256> = Hmac::new_from_slice(secret.as_bytes())?;
    let mut claims = HashMap::new();
    claims.insert("sub", "someone");
    let token = claims.sign_with_key(&key)?;
    Ok(token)
}

async fn write_http_msg(client: &mut TcpStream, hdrs: &HashMap<&str, &str>, is_req: bool) -> Result<String> {
    let msg = http_msg_from(hdrs, 128, is_req);
    let write = client.write_all(msg.as_bytes());
    timeout(DEFAULT_TIMEOUT, write).await??;

    Ok(msg)
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
    let req_sent = write_http_msg(client, hdrs, true).await?;
    let mut server = try_accept(server).await?;
    let req_recv = read(&mut server).await?;

    Ok((server, req_sent, req_recv))
}

fn parse_http_hdrs(buf: &[u8]) -> Result<HashMap<String, String>> {
    if buf.len() == 0 {
        return Err(anyhow!("empty buffer"));
    }

    let mut msg_hdr = [httparse::EMPTY_HEADER; 64];
    let mut msg = httparse::Request::new(&mut msg_hdr);
    
    let headers = if msg.parse(buf).is_ok() {
        msg.headers
    }
    else {
        let mut msg = httparse::Response::new(&mut msg_hdr);
        msg.parse(buf)?;
        msg.headers
    };

    let hdrs = headers.iter()
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

    let res = write_http_msg(&mut client, &hdrs, true).await;
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
    let req_hdrs = HashMap::from([
        ("backend", "server1"),
        ("authorization", token.as_str())
    ]);

    let (mut server1, req_sent, req_recv) = write_accept_read(&mut client, server1, &req_hdrs).await.unwrap();
    let mut hdrs_sent = parse_http_hdrs(req_sent.as_bytes()).unwrap();    
    let conn_id = client.local_addr().unwrap().port().to_string();
    hdrs_sent.insert(String::from("conn-id"), conn_id.clone());
    assert_http_hdr_eq(&req_recv, &hdrs_sent);
    assert_http_payload_eq(&req_sent, &req_recv);

    let res_hdrs = HashMap::from([
        ("signature", "server1"),
        ("conn-id", conn_id.as_str()),
    ]);

    let res_sent = write_http_msg(&mut server1, &res_hdrs, false).await.unwrap();
    let res_recv = read(&mut client).await.unwrap();
    let hdrs_recv = parse_http_hdrs(res_recv.as_bytes()).unwrap();    
    assert_http_hdr_eq(&res_recv, &hdrs_recv);
    assert_http_payload_eq(&res_sent, &res_recv);

    // give the pipeline some time to update its metrics
    time::sleep(Duration::from_millis(10)).await;

    let req_sent = write_http_msg(&mut client, &req_hdrs, true).await.unwrap();
    let req_recv = read(&mut server1).await.unwrap();
    assert_http_hdr_eq(&req_recv, &hdrs_sent);
    assert_http_payload_eq(&req_sent, &req_recv);

    let server2_req_recv = try_accept(server2).await;
    assert!(server2_req_recv.is_err());
}