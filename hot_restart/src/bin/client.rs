//! The HTTP/2 client of script/hot_restart_bench.sh.
//!
//! Opens an HTTP/2 connection without TLS to beeline and sends a request with the method KEEP
//! every INTERVAL ms. Once beeline sends GOAWAY, it finishes the request in flight, closes the
//! connection and reconnects. On the new connection, it sends a request with the method PROBE,
//! which only the new policy allows, and one with KEEP, which the new policy denies.
//!
//! Prints "ready" once its first request got a response. Once the new policy answered both
//! requests as expected, prints a JSON object with the latencies of the reconnect in ms:
//!   goaway_to_close     receives GOAWAY -> closes the old connection
//!   close_to_connect    closes the old connection -> new connection is established
//!   connect_to_response new connection is established -> first response under the new policy
//!   goaway_to_response  receives GOAWAY -> first response under the new policy
//!   gap                 last response on the old connection -> first one on the new connection
//!   latency             median latency of a request on the old connection
//! and the times of the GOAWAY and of the first response under the new policy in ns since the
//! epoch, which relate them to the logs of beeline.
use anyhow::{bail, ensure, Result};
use clap::Parser;
use hot_restart::*;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    fmt,
    io::{self, ErrorKind, Read, Write},
    net::{IpAddr, SocketAddr, TcpStream},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The HTTP/2 client of script/hot_restart_bench.sh, which reconnects once beeline sends GOAWAY.
#[derive(Parser)]
struct Args {
    /// The address of beeline, e.g. 127.0.0.1:48110
    proxy: SocketAddr,

    /// The IP the client binds to, beeline picks HTTP/2 for that of an HTTP/2 host
    src: IpAddr,

    /// The method of the requests on the old connection, the new policy denies it
    keep: String,

    /// The method of the first request on the new connection, the old policy denies it
    probe: String,

    /// Milliseconds between two requests on the old connection
    #[arg(long, default_value_t = 10.0)]
    interval: f64,

    /// Seconds to wait for the GOAWAY
    #[arg(long, default_value_t = 60.0)]
    wait: f64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before the epoch")
        .as_nanos() as u64
}

fn ms(from: u64, to: u64) -> f64 {
    (to as i64 - from as i64) as f64 / 1e6
}

/// A literal header field without indexing, whose name is in the static table (RFC 7541, 6.2.2).
fn literal(index: u8, value: &str) -> Vec<u8> {
    assert!(index < 0x10 && value.len() < 0x7F, "needs a longer integer encoding");
    let mut field = vec![index, value.len() as u8];
    field.extend_from_slice(value.as_bytes());
    field
}

/// :method, :scheme http, :path, :authority
fn header_block(method: &str) -> Vec<u8> {
    let mut block = literal(2, method);
    block.push(0x86);
    block.extend(literal(4, "/bench"));
    block.extend(literal(1, "beeline"));
    block
}

struct Goaway {
    at: u64,
    last_stream: u32,
    code: u32,
}

#[derive(PartialEq)]
enum Outcome {
    Ok,
    /// The data plane dropped the request.
    Denied,
    /// Beeline answered a request that it cannot forward, with a gRPC error and no body.
    Error,
    Reset,
    Timeout,
}

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Outcome::Ok => "ok",
            Outcome::Denied => "denied",
            Outcome::Error => "error",
            Outcome::Reset => "reset",
            Outcome::Timeout => "timeout",
        })
    }
}

/// Whether an error means that the peer closed the connection.
fn closed(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
    )
}

struct Conn {
    sock: TcpStream,
    buf: Vec<u8>,
    next_stream: u32,
    goaway: Option<Goaway>,
    received: u64,
}

impl Conn {
    fn connect(proxy: SocketAddr, src: IpAddr) -> Result<Self> {
        let sock = Socket::new(Domain::for_address(proxy), Type::STREAM, Some(Protocol::TCP))?;
        sock.bind(&SocketAddr::new(src, 0).into())?;
        sock.connect(&proxy.into())?;
        let mut sock = TcpStream::from(sock);
        sock.set_nodelay(true)?;

        sock.write_all(PREFACE)?;
        send(&mut sock, SETTINGS, 0, 0, &[])?;
        Ok(Self {
            sock,
            buf: Vec::new(),
            next_stream: 1,
            goaway: None,
            received: 0,
        })
    }

    /// The next frame other than SETTINGS and PING, None at the deadline.
    /// Fails with UnexpectedEof once the peer closed.
    fn frame(&mut self, deadline: Instant) -> io::Result<Option<Frame>> {
        loop {
            if let Some(frame) = pop_frame(&mut self.buf) {
                if control(&mut self.sock, &frame)? {
                    continue;
                }
                // the first one counts, h2 sends a second one when the client acked its PING
                if frame.typ == GOAWAY && self.goaway.is_none() && frame.payload.len() >= 8 {
                    let p = &frame.payload;
                    self.goaway = Some(Goaway {
                        at: self.received,
                        last_stream: u32::from_be_bytes(p[..4].try_into().unwrap()) & 0x7FFF_FFFF,
                        code: u32::from_be_bytes(p[4..8].try_into().unwrap()),
                    });
                }
                return Ok(Some(frame));
            }

            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(None);
            }
            self.sock.set_read_timeout(Some(left))?;
            let mut chunk = [0u8; 65536];
            let n = match self.sock.read(&mut chunk) {
                Ok(n) => n,
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Ok(None)
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            self.received = now();
            if n == 0 {
                return Err(io::Error::new(ErrorKind::UnexpectedEof, "closed by beeline"));
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn request(&mut self, method: &str) -> io::Result<Outcome> {
        let stream = self.next_stream;
        self.next_stream += 2;

        // the data plane only matches a HEADERS frame whose flags are END_HEADERS,
        // so every request has a body
        let sent = send(&mut self.sock, HEADERS, END_HEADERS, stream, &header_block(method))
            .and_then(|_| send(&mut self.sock, DATA, END_STREAM, stream, b"bench"));
        match sent {
            // the verdict of the sk_msg program fails the write
            Err(e) if e.kind() == ErrorKind::PermissionDenied => return Ok(Outcome::Denied),
            Err(e) => return Err(e),
            Ok(()) => {}
        }

        let mut body = Vec::new();
        let deadline = Instant::now() + REQUEST_TIMEOUT;
        while let Some(frame) = self.frame(deadline)? {
            if frame.stream != stream {
                continue;
            }
            if frame.typ == RST_STREAM {
                return Ok(Outcome::Reset);
            }
            if frame.typ == DATA {
                body.extend_from_slice(&frame.payload);
            }
            if frame.flags & END_STREAM != 0 {
                return Ok(if body == b"ok" {
                    Outcome::Ok
                } else {
                    Outcome::Error
                });
            }
        }
        Ok(Outcome::Timeout)
    }
}

/// The requests on the connection to the old instance.
struct Traffic {
    last_ok: u64,
    requests: u64,
    failed: u64,
    latencies: Vec<f64>,
}

/// Idles for the interval, a GOAWAY that arrives meanwhile ends it right away. Then sends a
/// request, unless a GOAWAY arrived. A request in flight when the GOAWAY arrives finishes first.
fn step(conn: &mut Conn, method: &str, interval: Duration, traffic: &mut Traffic) -> io::Result<()> {
    let until = Instant::now() + interval;
    while conn.goaway.is_none() && conn.frame(until)?.is_some() {}
    if conn.goaway.is_some() {
        return Ok(());
    }

    let sent = now();
    if conn.request(method)? == Outcome::Ok {
        traffic.last_ok = now();
        traffic.requests += 1;
        traffic.latencies.push(ms(sent, traffic.last_ok));
    } else {
        traffic.failed += 1;
    }
    Ok(())
}

fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    let mut values = values.to_vec();
    values.sort_by(f64::total_cmp);
    let mid = values.len() / 2;
    if values.len() % 2 == 1 {
        values[mid]
    } else {
        (values[mid - 1] + values[mid]) / 2.0
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let interval = Duration::from_secs_f64(args.interval / 1000.0);

    let mut old = Conn::connect(args.proxy, args.src)?;
    let res = old.request(&args.keep)?;
    ensure!(res == Outcome::Ok, "{} on the old instance: {res}", args.keep);
    // stdout is line buffered, the line goes out right away
    println!("ready");

    let mut traffic = Traffic {
        last_ok: now(),
        requests: 1,
        failed: 0,
        latencies: Vec::new(),
    };
    let deadline = Instant::now() + Duration::from_secs_f64(args.wait);
    while old.goaway.is_none() {
        match step(&mut old, &args.keep, interval, &mut traffic) {
            Ok(()) => {}
            Err(e) if closed(&e) && old.goaway.is_some() => break,
            Err(e) if closed(&e) => bail!("the old connection ended before a GOAWAY: {e}"),
            Err(e) => bail!(e),
        }
        ensure!(
            old.goaway.is_some() || Instant::now() < deadline,
            "no GOAWAY within {}s",
            args.wait
        );
    }
    let goaway = old.goaway.take().unwrap();

    drop(old);
    let closed = now();

    let mut new = Conn::connect(args.proxy, args.src)?;
    let connected = now();
    let res = new.request(&args.probe)?;
    let answered = now();
    ensure!(
        res == Outcome::Ok,
        "{} on the new connection: {res}, the old policy denies it",
        args.probe
    );
    let res = new.request(&args.keep)?;
    ensure!(
        res == Outcome::Denied,
        "{} on the new connection: {res}, the new policy denies it",
        args.keep
    );

    println!(
        "{}",
        serde_json::json!({
            "goaway_to_close": ms(goaway.at, closed),
            "close_to_connect": ms(closed, connected),
            "connect_to_response": ms(connected, answered),
            "goaway_to_response": ms(goaway.at, answered),
            "gap": ms(traffic.last_ok, answered),
            "latency": median(&traffic.latencies),
            "goaway_at": goaway.at,
            "answered_at": answered,
            "requests": traffic.requests,
            "failed": traffic.failed,
            "goaway_last_stream": goaway.last_stream,
            "goaway_code": goaway.code,
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn medians() {
        assert_eq!(median(&[]), 0.0);
        assert_eq!(median(&[3.0, 1.0, 2.0]), 2.0);
        assert_eq!(median(&[4.0, 1.0, 2.0, 3.0]), 2.5);
    }
}
