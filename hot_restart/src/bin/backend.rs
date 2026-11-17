//! The backend of script/hot_restart_bench.sh, beeline forwards the requests of the client to it.
//!
//! Answers every request with 200 and the body "ok", which tells the client that the data plane
//! forwarded its request. Beeline answers a request that it cannot forward itself, without a body.
use anyhow::Result;
use clap::Parser;
use hot_restart::*;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io::{self, Read},
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
};

/// The backend of script/hot_restart_bench.sh, which answers every request with 200 and "ok".
#[derive(Parser)]
struct Args {
    /// The address to listen on, e.g. 127.0.0.2:48111
    addr: SocketAddr,
}

/// Reads more bytes into the buffer, false once the peer closed.
fn fill(sock: &mut TcpStream, buf: &mut Vec<u8>) -> io::Result<bool> {
    let mut chunk = [0u8; 65536];
    let n = sock.read(&mut chunk)?;
    buf.extend_from_slice(&chunk[..n]);
    Ok(n > 0)
}

fn serve(mut sock: TcpStream) -> io::Result<()> {
    sock.set_nodelay(true)?;
    let mut buf = Vec::new();
    while buf.len() < PREFACE.len() {
        if !fill(&mut sock, &mut buf)? {
            return Ok(());
        }
    }
    buf.drain(..PREFACE.len());
    send(&mut sock, SETTINGS, 0, 0, &[])?;

    loop {
        let Some(frame) = pop_frame(&mut buf) else {
            if !fill(&mut sock, &mut buf)? {
                return Ok(());
            }
            continue;
        };
        if control(&mut sock, &frame)? {
            continue;
        }
        if (frame.typ == HEADERS || frame.typ == DATA) && frame.flags & END_STREAM != 0 {
            // :status 200, indexed in the static table. Without END_STREAM, the data
            // plane matches the response, which only has END_HEADERS set
            send(&mut sock, HEADERS, END_HEADERS, frame.stream, &[0x88])?;
            send(&mut sock, DATA, END_STREAM, frame.stream, b"ok")?;
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let sock = Socket::new(Domain::for_address(args.addr), Type::STREAM, Some(Protocol::TCP))?;
    sock.set_reuse_address(true)?;
    sock.bind(&args.addr.into())?;
    sock.listen(1024)?;
    let listener = TcpListener::from(sock);

    for sock in listener.incoming() {
        let sock = sock?;
        // the connection ends with an error when beeline exits
        thread::spawn(move || serve(sock).ok());
    }
    Ok(())
}
