//! End-to-end tests of the data plane. They need root, the crypto kernel module
//! (see the README), and a build with CONFIG=config/beeline/test.yaml.

use ::bytes::Bytes;
use beeline::Proxy;
use common::config::beeline::Config;
use hmac::{Hmac, Mac};
use jwt::{header::HeaderType, AlgorithmType, Header, SignWithKey, Token};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    mem::MaybeUninit,
    net::SocketAddr,
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::mpsc,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(2);
const WAIT_NOTHING: Duration = Duration::from_millis(300);

struct OpenObject(MaybeUninit<libbpf_rs::OpenObject>);

unsafe impl Send for OpenObject {}

/// Attaches a proxy with the config the data plane was built with and returns
/// its address. It is detached when the runtime of the test shuts down.
async fn proxy() -> SocketAddr {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

    let built = Path::new(env!("BEELINE_CONFIG"));
    let expected = Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/beeline/test.yaml");
    assert_eq!(
        Some(built),
        expected.canonicalize().ok().as_deref(),
        "build the tests with CONFIG=config/beeline/test.yaml"
    );
    let config: Config = serde_yaml::from_reader(std::fs::File::open(built).unwrap()).unwrap();

    let addr = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    tokio::spawn(async move {
        let mut open_obj = OpenObject(MaybeUninit::uninit());
        let proxy = Proxy::attach(addr, None, config, &mut open_obj.0).expect("attach proxy");
        proxy.listen().await
    });

    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return addr;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the proxy does not listen on {addr}");
}

/// Returns the length of the first HTTP/1.1 message in `buf`, if it is complete.
fn message_len(buf: &[u8]) -> Option<usize> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&buf[..end]).to_ascii_lowercase();
    let body = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .map_or(0, |v| v.trim().parse().unwrap());
    (buf.len() >= end + body).then_some(end + body)
}

async fn read_message(stream: &mut TcpStream, buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    loop {
        if let Some(len) = message_len(buf) {
            return Some(buf.drain(..len).collect());
        }
        match stream.read_buf(buf).await {
            Ok(0) | Err(_) => return None,
            Ok(_) => (),
        }
    }
}

/// An HTTP/1.1 server that hands every request it receives to the test, along
/// with the number of the connection it came in on.
struct Upstream {
    requests: mpsc::UnboundedReceiver<(usize, String)>,
    conns: Arc<AtomicUsize>,
}

impl Upstream {
    /// Responds with 204 and no content length to `/204`, with 404 to `/404`,
    /// not at all to `/hold`, and with 200 to anything else.
    async fn bind(addr: &str, name: &'static str) -> Upstream {
        let listener = TcpListener::bind(addr).await.expect("bind upstream");
        let (tx, requests) = mpsc::unbounded_channel();
        let conns = Arc::new(AtomicUsize::new(0));

        let counter = conns.clone();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let conn = counter.fetch_add(1, Ordering::SeqCst);
                let tx = tx.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    while let Some(req) = read_message(&mut stream, &mut buf).await {
                        let req = String::from_utf8(req).unwrap();
                        let line = req.lines().next().unwrap_or_default().to_string();
                        let _ = tx.send((conn, req));

                        let res = if line.contains(" /hold ") {
                            continue;
                        } else if line.contains(" /204 ") {
                            format!("HTTP/1.1 204 No Content\r\nX-Server: {name}\r\n\r\n")
                        } else {
                            let status = if line.contains(" /404 ") { 404 } else { 200 };
                            format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\nX-Server: {name}\r\n\r\n{name}", name.len())
                        };
                        if stream.write_all(res.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        Upstream { requests, conns }
    }

    async fn next(&mut self) -> (usize, String) {
        timeout(WAIT, self.requests.recv())
            .await
            .expect("no request arrived upstream")
            .unwrap()
    }

    async fn assert_nothing(&mut self) {
        let res = timeout(WAIT_NOTHING, self.requests.recv()).await;
        assert!(res.is_err(), "unexpected request upstream: {res:?}");
    }
}

/// The servers of all HTTP/1.1 hosts in test.yaml.
async fn upstreams() -> [Upstream; 3] {
    [
        Upstream::bind("127.0.0.1:48001", "server1").await,
        Upstream::bind("127.0.0.1:48002", "server2").await,
        Upstream::bind("127.0.0.1:48003", "server3").await,
    ]
}

struct Client {
    stream: TcpStream,
    buf: Vec<u8>,
}

impl Client {
    async fn connect(addr: SocketAddr) -> Client {
        let stream = TcpStream::connect(addr).await.unwrap();
        Client {
            stream,
            buf: Vec::new(),
        }
    }

    /// Sends `req` and returns the response, or [`None`] if the data plane
    /// drops the request.
    async fn send(&mut self, req: &str) -> Option<String> {
        // a dropped sk_msg fails the write with EACCES
        self.stream.write_all(req.as_bytes()).await.ok()?;
        let res = timeout(WAIT, read_message(&mut self.stream, &mut self.buf)).await;
        res.ok()
            .flatten()
            .map(|res| String::from_utf8(res).unwrap())
    }
}

fn req(method: &str, path: &str, hdrs: &[&str], body: &str) -> String {
    let hdrs: String = hdrs.iter().map(|h| format!("{h}\r\n")).collect();
    format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{hdrs}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// Returns a JWT signed with HS256, with the header the JWT filter expects.
fn jwt(secret: &str, issuer: &str) -> String {
    let key: Hmac<Sha256> = Hmac::new_from_slice(secret.as_bytes()).unwrap();
    let header = Header {
        algorithm: AlgorithmType::Hs256,
        type_: Some(HeaderType::JsonWebToken),
        ..Default::default()
    };
    let claims = BTreeMap::from([("sub", "someone"), ("iss", issuer)]);
    let token = Token::new(header, claims).sign_with_key(&key).unwrap();
    token.as_str().to_string()
}

fn served_by(res: Option<String>, name: &str) {
    let res = res.expect("no response");
    assert!(res.contains(&format!("X-Server: {name}\r\n")), "{res}");
}

#[tokio::test]
async fn it_routes_by_path_and_header() {
    let addr = proxy().await;
    let [mut s1, mut s2, mut s3] = upstreams().await;

    let mut client = Client::connect(addr).await;
    served_by(
        client
            .send(&req("GET", "/api", &["backend: server2"], ""))
            .await,
        "server2",
    );
    s2.next().await;

    // the path matches the route of server2, the header does not
    let mut client = Client::connect(addr).await;
    served_by(
        client
            .send(&req("GET", "/api", &["backend: server1"], ""))
            .await,
        "server1",
    );
    s1.next().await;

    let mut client = Client::connect(addr).await;
    served_by(
        client
            .send(&req("GET", "/api", &["backend: server"], ""))
            .await,
        "server3",
    );
    served_by(client.send(&req("GET", "/x", &[], "")).await, "server3");
    s3.next().await;
    s3.next().await;

    s1.assert_nothing().await;
    s2.assert_nothing().await;
}

#[tokio::test]
async fn it_does_not_reuse_the_header_of_a_previous_request() {
    let addr = proxy().await;
    let [_, mut s2, mut s3] = upstreams().await;

    let mut client = Client::connect(addr).await;
    served_by(
        client
            .send(&req("GET", "/api", &["backend: server2"], ""))
            .await,
        "server2",
    );
    s2.next().await;

    let mut client = Client::connect(addr).await;
    served_by(client.send(&req("GET", "/api", &[], "")).await, "server3");
    s3.next().await;
}

#[tokio::test]
async fn it_mutates_headers() {
    let addr = proxy().await;
    let [_, mut s2, _] = upstreams().await;
    let mut client = Client::connect(addr).await;

    let hdrs = ["backend: server2", "x-remove-me: please"];
    for _ in 0..2 {
        served_by(client.send(&req("GET", "/api", &hdrs, "")).await, "server2");
        let (_, req) = s2.next().await;
        assert_eq!(
            req,
            "GET /api HTTP/1.1\r\nHost: 127.0.0.1\r\nbackend: server2\r\nContent-Length: 0\r\nx-processed-by: beeline\r\n\r\n"
        );
    }
}

#[tokio::test]
async fn it_reuses_the_upstream_connection() {
    let addr = proxy().await;
    let [mut s1, _, _] = upstreams().await;
    let mut client = Client::connect(addr).await;

    for _ in 0..3 {
        served_by(
            client
                .send(&req("GET", "/", &["backend: server1"], ""))
                .await,
            "server1",
        );
        assert_eq!(s1.next().await.0, 0);
    }
    assert_eq!(s1.conns.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn it_does_not_multiplex_conns() {
    let addr = proxy().await;
    let [mut s1, _, _] = upstreams().await;
    let mut client1 = Client::connect(addr).await;
    let mut client2 = Client::connect(addr).await;

    // the upstream holds back the responses, so its connections stay busy
    let held = req("GET", "/hold", &["backend: server1"], "");
    client1.stream.write_all(held.as_bytes()).await.unwrap();
    let (conn1, _) = s1.next().await;
    client2.stream.write_all(held.as_bytes()).await.unwrap();
    let (conn2, _) = s1.next().await;

    assert_ne!(conn1, conn2);
}

#[tokio::test]
async fn it_forwards_bodies_and_responses() {
    let addr = proxy().await;
    let [_, _, mut s3] = upstreams().await;
    let mut client = Client::connect(addr).await;

    let post = req("POST", "/x", &[], "0123456789");
    served_by(client.send(&post).await, "server3");
    assert_eq!(s3.next().await.1, post);

    let res = client.send(&req("GET", "/204", &[], "")).await;
    assert_eq!(
        res.as_deref(),
        Some("HTTP/1.1 204 No Content\r\nX-Server: server3\r\n\r\n")
    );
    s3.next().await;

    let res = client.send(&req("GET", "/404", &[], "")).await.unwrap();
    assert!(res.starts_with("HTTP/1.1 404 "), "{res}");
    s3.next().await;
}

#[tokio::test]
async fn it_enforces_rbac_by_method() {
    let addr = proxy().await;
    let [_, _, mut s3] = upstreams().await;

    for method in ["PUT", "DELETE"] {
        let mut client = Client::connect(addr).await;
        assert_eq!(
            client.send(&req(method, "/admin", &[], "x")).await,
            None,
            "{method}"
        );
        s3.assert_nothing().await;
    }

    for method in ["GET", "POST", "PATCH"] {
        let mut client = Client::connect(addr).await;
        served_by(
            client.send(&req(method, "/admin", &[], "x")).await,
            "server3",
        );
        s3.next().await;
    }
}

#[tokio::test]
async fn it_forwards_valid_jwt() {
    let addr = proxy().await;
    let [_, _, mut s3] = upstreams().await;
    let token = jwt("testtest12345678", "beeline");

    for auth in [
        format!("Authorization: Bearer {token}"),
        format!("authorization: bearer {token}"),
    ] {
        let mut client = Client::connect(addr).await;
        for _ in 0..2 {
            served_by(
                client.send(&req("GET", "/jwt", &[&auth], "")).await,
                "server3",
            );
            let (_, req) = s3.next().await;
            assert_eq!(
                req,
                "GET /jwt HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 0\r\nx-processed-by: beeline\r\n\r\n"
            );
        }
    }
}

#[tokio::test]
async fn it_drops_invalid_jwt() {
    let addr = proxy().await;
    let [_, _, mut s3] = upstreams().await;

    let invalid = [
        vec![format!(
            "Authorization: Bearer {}",
            jwt("invalid_secret", "beeline")
        )],
        vec![format!(
            "Authorization: Bearer {}",
            jwt("testtest12345678", "other")
        )],
        vec![format!(
            "Authorization: Basic {}",
            jwt("testtest12345678", "beeline")
        )],
        vec![],
    ];
    for hdrs in invalid {
        let hdrs: Vec<&str> = hdrs.iter().map(String::as_str).collect();
        let mut client = Client::connect(addr).await;
        assert_eq!(
            client.send(&req("GET", "/jwt", &hdrs, "")).await,
            None,
            "{hdrs:?}"
        );
        s3.assert_nothing().await;
    }
}

/// An HTTP/2 server that hands the path, the backend header and the body of
/// every request it receives to the test.
async fn h2_upstream(addr: &str, name: &'static str) -> mpsc::UnboundedReceiver<String> {
    let listener = TcpListener::bind(addr).await.expect("bind upstream");
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            let tx = tx.clone();
            tokio::spawn(async move {
                let Ok(mut conn) = http2::server::handshake(sock).await else {
                    return;
                };
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    let (parts, mut body) = req.into_parts();
                    let mut data = Vec::new();
                    while let Some(Ok(chunk)) = body.data().await {
                        let _ = body.flow_control().release_capacity(chunk.len());
                        data.extend_from_slice(&chunk);
                    }
                    let backend = parts.headers.get("backend").map(|v| v.to_str().unwrap());
                    let _ = tx.send(format!(
                        "{} {backend:?} {}",
                        parts.uri.path(),
                        String::from_utf8_lossy(&data)
                    ));

                    let res = http::Response::builder()
                        .header("x-server", name)
                        .body(())
                        .unwrap();
                    let mut send = respond.send_response(res, false).unwrap();
                    let _ = send.send_data(Bytes::from(name), true);
                }
            });
        }
    });
    rx
}

async fn h2_next(rx: &mut mpsc::UnboundedReceiver<String>) -> String {
    timeout(WAIT, rx.recv())
        .await
        .expect("no request arrived upstream")
        .unwrap()
}

async fn h2_client(addr: SocketAddr) -> http2::client::SendRequest<Bytes> {
    let sock = TcpSocket::new_v4().unwrap();
    sock.bind("127.0.0.2:0".parse().unwrap()).unwrap();
    let sock = sock.connect(addr).await.unwrap();
    let (client, conn) = http2::client::handshake(sock).await.unwrap();
    tokio::spawn(conn);
    client
}

async fn h2_post(
    client: &mut http2::client::SendRequest<Bytes>,
    hdrs: &[(&str, &str)],
    body: &str,
) -> String {
    let mut req = http::Request::builder()
        .method("POST")
        .uri("http://127.0.0.1/h2");
    for (k, v) in hdrs {
        req = req.header(*k, *v);
    }

    let send = async {
        let mut client = client.clone().ready().await.unwrap();
        let (res, mut stream) = client.send_request(req.body(()).unwrap(), false).unwrap();
        stream
            .send_data(Bytes::from(body.to_string()), true)
            .unwrap();
        let res = res.await.unwrap();
        res.headers()["x-server"].to_str().unwrap().to_string()
    };
    timeout(WAIT, send).await.expect("no HTTP/2 response")
}

#[tokio::test]
async fn it_routes_http2_by_headers_from_the_dynamic_table() {
    let addr = proxy().await;
    let mut h2s1 = h2_upstream("127.0.0.2:48011", "h2-server1").await;
    let mut h2s2 = h2_upstream("127.0.0.2:48012", "h2-server2").await;

    // the client indexes the header after the first request, so later requests
    // refer to it in the HPACK dynamic table
    let mut client = h2_client(addr).await;
    for body in ["1", "2", "3"] {
        assert_eq!(
            h2_post(&mut client, &[("backend", "server2")], body).await,
            "h2-server2"
        );
        assert_eq!(
            h2_next(&mut h2s2).await,
            format!("/h2 Some(\"server2\") {body}")
        );
    }

    let mut client = h2_client(addr).await;
    assert_eq!(h2_post(&mut client, &[], "4").await, "h2-server1");
    assert_eq!(h2_next(&mut h2s1).await, "/h2 None 4");
}
