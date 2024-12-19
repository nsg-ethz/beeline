use baseline::Proxy;
use common::test;
use std::net::SocketAddr;

async fn setup() -> SocketAddr {
    let (tx, rx) = tokio::sync::oneshot::channel();

    tokio::spawn(async move {
        let mut port = 3000;
        let proxy = loop {
            match Proxy::new(format!("127.0.0.1:{port}"), test::config()) {
                Ok(proxy) => break proxy,
                Err(_) => port += 1,
            }
        };

        tx.send(proxy.address).unwrap();

        proxy.listen().await
    });

    rx.await.unwrap()
}

#[tokio::test]
async fn it_drops_invalid_jwt() {
    let addr = setup().await;
    test::it_drops_invalid_jwt(addr).await;
}

#[tokio::test]
async fn it_forwards_valid_jwt() {
    let addr = setup().await;
    test::it_forwards_valid_jwt(addr).await;
}

#[tokio::test]
async fn it_does_not_multiplex_conns() {
    let addr = setup().await;
    test::it_does_not_multiplex_conns(addr).await;
}
