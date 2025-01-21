use anyhow::Result;
use hyper::server::conn::http1::Builder;
use log::{debug, error, info};
use std::{net::SocketAddr, thread};
use tokio::{
    net::{TcpListener, TcpSocket, TcpStream},
    runtime::{Builder as RuntimeBuilder, Handle},
};

pub(crate) fn run<F>(addr: SocketAddr, per_connection: F)
where
    F: Fn(TcpStream, &mut Builder, Handle) + Clone + Send + 'static,
{
    info!("Listening on {addr}");

    // Spawn a thread for each available core, minus one, since we'll
    // reuse the main thread as a server thread as well.
    let num_cpus = num_cpus::get();
    for _ in 1..num_cpus {
        let per_connection = per_connection.clone();
        thread::spawn(move || {
            server_thread(&addr, per_connection);
        });
    }
    server_thread(&addr, per_connection);
}

fn server_thread<F>(addr: &SocketAddr, per_connection: F)
where
    F: Fn(TcpStream, &mut Builder, Handle) + Send + 'static,
{
    let mut http = Builder::new();

    let core = RuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let handle = core.handle();

    // For every accepted connection, spawn an HTTP task
    let server = async move {
        let tcp = reuse_listener(addr).expect("Failed to bind to address");
        loop {
            match tcp.accept().await {
                Ok((sock, _)) => {
                    debug!("Accepted connection {:?}", sock.peer_addr().unwrap());
                    let _ = sock.set_nodelay(true);
                    per_connection(sock, &mut http, handle.clone());
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e)
                }
            }
        }
    };

    core.block_on(server);
}

fn reuse_listener(addr: &SocketAddr) -> Result<TcpListener> {
    let socket = TcpSocket::new_v4()?;
    socket.set_reuseport(true)?;
    socket.set_reuseaddr(true)?;
    socket.bind(*addr)?;

    let listener = socket.listen(1024)?;
    Ok(listener)
}
