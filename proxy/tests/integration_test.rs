use ebpf::{config::Config, Proxy};
use std::{mem::MaybeUninit, ops::{Deref, DerefMut}, path::PathBuf};
use tokio::net::TcpStream;

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

async fn setup() -> TcpStream {
    let mut config = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    config.push("../config/debug.yaml");
    let config = std::fs::File::open(config).unwrap();
    let config: Config = serde_yaml::from_reader(config).unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let mut open_obj = OpenObject::new();
        let mut port = 3000;
        let proxy = loop {
            match Proxy::attach(format!("127.0.0.1:{port}"), config.clone(), &mut open_obj) {
                Ok(proxy) => break proxy,
                Err(_) => port += 1
            }
        };

        tx.send(proxy.address).unwrap();

        proxy.listen().await
    });

    let proxy_addr = rx.await.unwrap();
    let client = loop {
        match TcpStream::connect(&proxy_addr).await {
            Ok(client) => break client,
            Err(_) => continue
        }
    };

    client
}

#[tokio::test]
async fn it_drops_invalid_jwt() {
    let client = setup().await;
    tests::it_drops_invalid_jwt(client).await;
}

#[tokio::test]
async fn it_forwards_valid_jwt() {
    let client = setup().await;
    tests::it_forwards_valid_jwt(client).await;
}