use anyhow::Result;
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use proxy::Proxy;
use proxy::config::Config;
use rand::{distributions::Alphanumeric, Rng};
use sha2::Sha256;
use std::{collections::HashMap, mem::MaybeUninit, ops::{Deref, DerefMut}, path::PathBuf};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, task::JoinHandle, time::*};

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(10);

struct OpenObject {
    inner: MaybeUninit<libbpf_rs::OpenObject>
}

impl OpenObject {

    pub fn new() -> Self {
        Self {
            inner: MaybeUninit::uninit()
        }
    }

}

impl Deref for OpenObject {

    type Target = MaybeUninit<libbpf_rs::OpenObject>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }

}

impl DerefMut for OpenObject {

    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }

}

unsafe impl Send for OpenObject {}

async fn test_config() -> (Config, TcpListener, TcpListener) {    
    let mut config = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    config.push("../config/debug.yaml");
    let config = std::fs::File::open(config).unwrap();
    let config: Config = serde_yaml::from_reader(config).unwrap();

    let server1 = TcpListener::bind("127.0.0.1:8001").await.unwrap();
    let server2 = TcpListener::bind("127.0.0.1:8002").await.unwrap();

    (config, server1, server2)
}

async fn setup() -> (JoinHandle<Result<()>>, TcpStream, TcpListener, TcpListener) {
    _ = env_logger::try_init();

    let (config, server1, server2) = test_config().await;
    let proxy_addr = "127.0.0.1:3000";

    let proxy = tokio::spawn(async move {
        let mut open_obj = OpenObject::new();
        let proxy = Proxy::attach(&proxy_addr, config, &mut open_obj).unwrap();
        proxy.listen().await
    });

    let client = loop {
        match TcpStream::connect(&proxy_addr).await {
            Ok(client) => break client,
            Err(_) => continue
        }
    };

    (proxy, client, server1, server2)
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

async fn read(server: &mut TcpStream, len: usize) -> Result<String> {
    let mut req_recv = vec![0; len];
    let read = server.read(&mut req_recv);
    timeout(DEFAULT_TIMEOUT, read).await??;

    let req_recv = String::from_utf8(req_recv)?;
    Ok(req_recv)
}

async fn write_accept_read(client: &mut TcpStream, server: TcpListener, hdrs: &HashMap<&str, &str>) -> Result<(TcpStream, String, String)> {
    let req_sent = write(client, hdrs).await?;
    let mut server = try_accept(server).await?;
    let req_recv = read(&mut server, req_sent.len()).await?;

    Ok((server, req_sent, req_recv))
}

#[tokio::test]
async fn it_routes_to_correct_destination() {
    let (proxy, mut client, server1, server2) = setup().await;
    let hdrs = HashMap::from([("backend", "server1")]);

    let (_, req_sent, req_recv) = write_accept_read(&mut client, server1, &hdrs).await.unwrap();
    assert_eq!(req_sent, req_recv);

    let server2_req_recv = try_accept(server2).await;
    assert!(server2_req_recv.is_err());
    
    proxy.abort();
}

#[tokio::test]
async fn it_drops_invalid_jwt() {
    let (proxy, mut client, server1, server2) = setup().await;
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

    proxy.abort();
}

#[tokio::test]
async fn it_forwards_valid_jwt() {
    let (proxy, mut client, server1, server2) = setup().await;
    let token = generate_jwt("some-secret").unwrap();
    let token = format!("Bearer {token}");
    let hdrs = HashMap::from([
        ("backend", "server1"),
        ("Authorization", token.as_str())
    ]);

    let (mut server1, req_sent, req_recv) = write_accept_read(&mut client, server1, &hdrs).await.unwrap();
    assert_eq!(req_sent, req_recv);

    // the second request with the same token should be handled in eBPF only
    let req_sent = write(&mut client, &hdrs).await.unwrap();
    let req_recv = read(&mut server1, req_sent.len()).await.unwrap();
    assert_eq!(req_sent, req_recv);

    let server2_req_recv = try_accept(server2).await;
    assert!(server2_req_recv.is_err());

    proxy.abort();
}