use anyhow::Result;
use proxy::Proxy;
use proxy::config::Config;
use rand::{distributions::Alphanumeric, Rng};
use std::{mem::MaybeUninit, ops::{Deref, DerefMut}, path::PathBuf};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::{TcpListener, TcpStream}, time::*};

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

fn random_payload(len: usize) -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .collect()
}

async fn setup() -> (TcpStream, TcpListener, TcpListener) {
    env_logger::init();
    let (config, server1, server2) = test_config().await;
    let proxy_addr = "127.0.0.1:3000";

    tokio::spawn(async move {
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

    (client, server1, server2)
}

fn req_header_to(backend: u8) -> String {
    format!(
        "POST / HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         backend: server{}\r\n\
         \r\n\r\n", backend).to_string()
}

async fn write_read(client: &mut TcpStream, server: &mut TcpStream, headers: String) -> Result<(String, String)> {
    let req_sent = [headers.as_bytes(), random_payload(128).as_slice()].concat();
    client.write_all(&req_sent).await?;

    let mut req_recv = vec![0; req_sent.len()];
    server.read(&mut req_recv).await?;

    let req_sent = String::from_utf8(req_sent.to_vec()).unwrap();
    let req_recv = String::from_utf8(req_recv).unwrap();
    Ok((req_sent, req_recv))
}

async fn write_accept_read(client: &mut TcpStream, server: TcpListener, headers: String) -> Result<(TcpStream, String, String)> {
    let req_sent = [headers.as_bytes(), random_payload(128).as_slice()].concat();
    client.write_all(&req_sent).await?;

    let mut server = server.accept().await.unwrap().0;

    let mut req_recv = vec![0; req_sent.len()];
    server.read(&mut req_recv).await?;

    let req_sent = String::from_utf8(req_sent.to_vec()).unwrap();
    let req_recv = String::from_utf8(req_recv).unwrap();
    Ok((server, req_sent, req_recv))
}

#[tokio::test]
async fn it_routes_to_correct_destination() {
    let (mut client, server1, server2) = setup().await;
    let hdrs = req_header_to(1);

    let (_, req_sent, req_recv) = write_accept_read(&mut client, server1, hdrs).await.unwrap();
    assert_eq!(req_sent, req_recv);

    let server2_req_recv = timeout(Duration::from_millis(10), server2.accept()).await;
    assert!(server2_req_recv.is_err());
}

// #[tokio::test]
// async fn it_updates_metrics_correctly() {
//     let (mut client, server1, server2) = setup().await;
//     let hdrs = req_header_to(1);

//     let (_, req_sent, req_recv) = write_accept_read(&mut client, server1, hdrs).await.unwrap();
//     assert_eq!(req_sent, req_recv);

//     let server2_req_recv = timeout(Duration::from_millis(10), server2.accept()).await;
//     assert!(server2_req_recv.is_err());
// }