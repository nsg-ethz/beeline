use proxy::Proxy;
use common::config::{Config, Filter, Host, Route, Destination, Spec};
use rand::{distributions::Alphanumeric, Rng};
use core::str;
use std::{collections::HashMap, io::{Read, Write}, net::{TcpListener, TcpStream}, thread};

static LOCAL_HOST: &str = "127.0.0.1";
static SERVER1_PORT: u16 = 8001;
static SERVER2_PORT: u16 = 8002;

fn test_config() -> (Config, TcpListener, TcpListener) {
    let server1 = TcpListener::bind(format!("{}:{}", LOCAL_HOST, SERVER1_PORT)).unwrap();
    let server2 = TcpListener::bind(format!("{}:{}", LOCAL_HOST, SERVER2_PORT)).unwrap();
    
    let hosts = vec![
        Host {
            name: "server1".to_string(),
            address: LOCAL_HOST.to_string()
        },
        Host {
            name: "server2".to_string(),
            address: LOCAL_HOST.to_string()
        }
    ];

    let routes = vec![
        Route {
            destination: Destination {
                host: "server1".to_string(),
                port: server1.local_addr().unwrap().port()
            }
        },
        Route {
            destination: Destination {
                host: "server2".to_string(),
                port: server2.local_addr().unwrap().port()
            }
        }
    ];

    let filters = vec![
        Filter {
            patterns: HashMap::from([
                ("backend".to_string(), "server1".to_string()),
            ]),
            route: vec![routes[0].clone()],
            mods: None
        },
        Filter {
            patterns: HashMap::from([
                ("backend".to_string(), "server2".to_string()),
            ]),
            route: vec![routes[1].clone()],
            mods: None
        },
    ];

    let config = Config {
        hosts,
        spec: Spec {
            http: filters
        }
    };

    (config, server1, server2)
}

fn random_payload(len: usize) -> Vec<u8> {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .collect()
}

fn setup() -> (TcpStream, TcpStream, TcpStream) {
    env_logger::init();
    let (config, socket1, socket2) = test_config();
    let proxy_addr = format!("{}:3000", LOCAL_HOST);
    let mut proxy = Proxy::new(proxy_addr.clone(), config).unwrap();
    proxy.attach().unwrap();

    let server1 = thread::spawn(move || {
        socket1.accept().unwrap().0
    });

    let server2 = thread::spawn(move || {
        socket2.accept().unwrap().0
    });

    thread::spawn(move || {
        _ = proxy.listen();
    });

    let server1 = server1.join().unwrap();
    let server2 = server2.join().unwrap();

    let client = loop {
        match TcpStream::connect(proxy_addr.clone()) {
            Ok(client) => break client,
            Err(_) => continue
        }
    };

    (client, server1, server2)
}

#[test]
fn it_routes_to_correct_destination() {
    let (mut client, mut server1, mut server2) = setup();

    let req_sent = b"POST / HTTP/1.1\r\n\
                     Host: 127.0.0.1\r\n\
                     backend: server1\r\n\
                     \r\n\r\n";
    let req_sent = [req_sent, random_payload(128).as_slice()].concat();

    client.write_all(req_sent.as_slice()).unwrap();

    let mut req_recv = vec![0; req_sent.len()];
    server1.read(&mut req_recv).unwrap();

    let req_sent = String::from_utf8(req_sent).unwrap();
    let req_recv = String::from_utf8(req_recv).unwrap();
    assert_eq!(req_sent, req_recv);

    let mut req_recv = vec![0; req_sent.len()];
    let len = server2.read(&mut req_recv).unwrap();
    assert_eq!(len, 0);
}