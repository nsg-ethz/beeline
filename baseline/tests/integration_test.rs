use baseline::Proxy;
use tokio::net::TcpStream;
use common::test;

async fn setup() -> TcpStream {
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let mut port = 3000;
        let proxy = loop {
            match Proxy::new(format!("127.0.0.1:{port}"), test::config()) {
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
    test::it_drops_invalid_jwt(client).await;
}

#[tokio::test]
async fn it_forwards_valid_jwt() {
    let client = setup().await;
    test::it_forwards_valid_jwt(client).await;
}