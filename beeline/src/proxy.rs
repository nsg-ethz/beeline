use crate::bpf::{types::*, TypedLookUp, *};
use ::bytes::Bytes;
use anyhow::{anyhow, bail, Context, Result};
use as_bytes::AsBytes;
use beeper::{
    http1,
    pseudo_header::{METHOD, PATH, STATUS},
    MatchId, MessageBuffer,
};
use common::{
    compiler::Variable,
    config::beeline::{Config, TlsConfig},
    net::{get_gw_ip, TryIntoRawOctets},
    Compiler,
};
use http::{header::AUTHORIZATION, Request, Response, StatusCode};
use http2::{client, server};
use ktls::{CorkStream, KtlsCipherSuite, KtlsCipherType, KtlsVersion};
use libbpf_rs::{
    set_print,
    skel::{OpenSkel, SkelBuilder},
    Link, MapCore, MapFlags, MapHandle, MapType, PrintLevel,
};
use libc::exit;
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use std::{
    env,
    io::Cursor,
    mem::MaybeUninit,
    net::{IpAddr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    signal::unix::{signal, SignalKind},
    sync::Mutex,
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, trace, warn, Level};

pub mod bpf;

/// The match id the data plane reads as "not captured".
const NO_MATCH: u8 = 0xFF;

/// The parsers for the filter context variables, along with the match id every
/// variable has in each of them.
struct Parsers {
    h1: http1::Parser,
    h2: beeper::http2::Parser,
    h1_preface: MatchId,
    h1_mids: Vec<u8>,
    h2_mids: Vec<u8>,
}

/// Configures the parsers to capture the filter context variables.
///
/// The match ids only depend on `vars`, so every call hands out the same ones.
fn new_parsers(vars: &[Variable]) -> Result<Parsers> {
    let mut h1 = http1::Parser::new();
    let mut h2 = beeper::http2::Parser::new();
    let h1_preface = h1.match_http2_preface()?;
    let mut h1_mids = Vec::new();
    let mut h2_mids = Vec::new();

    for var in vars {
        let h1_mid = match var.name() {
            "preface" => h1_preface,
            "method" => h1.capture_hdr(METHOD)?,
            "path" => h1.capture_hdr(PATH)?,
            "status_code" => h1.capture_hdr(STATUS)?,
            "jwt_claims" | "jwt_sig" => h1.capture_hdr(AUTHORIZATION)?,
            name => h1.capture_hdr(name)?,
        };
        h1_mids.push(h1_mid.into());

        let h2_mid = match var.name() {
            "preface" | "jwt_claims" | "jwt_sig" => NO_MATCH,
            "method" => h2.capture_hdr(METHOD)?.into(),
            "path" => h2.capture_hdr(PATH)?.into(),
            "status_code" => h2.capture_hdr(STATUS)?.into(),
            name => h2.capture_hdr(name)?.into(),
        };
        h2_mids.push(h2_mid);
    }

    Ok(Parsers {
        h1,
        h2,
        h1_preface,
        h1_mids,
        h2_mids,
    })
}

/// Frees the HPACK dynamic tables the parsers keep for the connection between
/// `a` and `b`. A parser keys them by the socket that sends, so both directions
/// are freed.
fn forget_conn(parsers: &[beeper::http2::AttachedParser], a: SocketAddr, b: SocketAddr) {
    for parser in parsers {
        for (local, remote) in [(a, b), (b, a)] {
            if let Err(e) = parser.forget_conn(local, remote) {
                warn!("Failed to forget HTTP/2 connection {local} -> {remote}: {e}");
            }
        }
    }
}

fn add_pqueue_to_fib<M: MapCore>(map: &M, key: fib_key) -> Result<()> {
    let key = unsafe { key.as_bytes() };
    if map.lookup(&key, MapFlags::empty())?.is_some() {
        return Ok(());
    }

    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        map_flags: libbpf_sys::BPF_ANY,
        // bpf_map_create_opts might have padding fields on some platform
        ..Default::default()
    };

    let pqueue = MapHandle::create(
        MapType::Queue,
        Some("fib_queue"),
        0,
        size_of::<sock_key>() as u32,
        8192,
        &opts,
    )?;

    let val = pqueue.as_fd().as_raw_fd().to_ne_bytes();

    match map.update(&key, &val, MapFlags::ANY) {
        Ok(_) => Ok(()),
        Err(e) => {
            if e.kind() == libbpf_rs::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                bail!(e)
            }
        }
    }
}

fn update_map<M: MapCore, K: AsBytes, V: AsBytes>(map: &M, key: &K, val: &V) -> Result<()> {
    let key = unsafe { key.as_bytes() };
    let val = unsafe { val.as_bytes() };

    map.update(&key, &val, MapFlags::ANY)?;
    Ok(())
}

fn delete_map<M: MapCore, K: AsBytes>(map: &M, key: &K) -> Result<()> {
    let key = unsafe { key.as_bytes() };

    map.delete(&key)?;
    Ok(())
}

fn init_dataplane(config: Config, rodata: &mut rodata) -> Result<()> {
    let vars = Compiler::new(config.clone()).get_ctx_vars();
    let parsers = new_parsers(&vars)?;
    if vars.len() > rodata.h1_mids.len() {
        bail!("Parsing too many patterns.")
    }

    rodata.h1_preface_mid = parsers.h1_preface.into();
    rodata.h1_mids[..vars.len()].copy_from_slice(&parsers.h1_mids);
    rodata.h2_mids[..vars.len()].copy_from_slice(&parsers.h2_mids);

    if let Some(network) = &config.network {
        let addr_raw = network.addr.try_into_ne_octets()?;
        rodata.ip4_start = addr_raw;
        rodata.ip4_end = addr_raw + network.len();

        let gw_raw = get_gw_ip(network.addr).try_into_ne_octets()?;
        rodata.gw = gw_raw;
    }

    Ok(())
}

fn print(level: PrintLevel, msg: String) {
    let msg = msg.trim_start_matches("libbpf:").trim();

    match level {
        PrintLevel::Debug => debug!(target: "libbpf", "{}", msg),
        PrintLevel::Info => info!(target: "libbpf", "{}", msg),
        PrintLevel::Warn => warn!(target: "libbpf", "{}", msg),
    }
}

pub struct Proxy<'obj> {
    pub address: SocketAddr,
    pub tls: Option<TlsConfig>,
    pub config: Config,

    skel: ProxySkel<'obj>,
    #[allow(dead_code)]
    sockops: Link,
    #[allow(dead_code)]
    parsers: (
        Vec<http1::AttachedParser>,
        Arc<Vec<beeper::http2::AttachedParser>>,
    ),
    h1_upstream_pool: Arc<Mutex<Vec<TcpStream>>>,
}

unsafe impl<'obj> Send for Proxy<'obj> {}

unsafe impl<'obj> Sync for Proxy<'obj> {}

impl<'obj> Proxy<'obj> {
    pub fn attach<A: ToSocketAddrs>(
        address: A,
        tls: Option<TlsConfig>,
        config: Config,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        set_print(Some((PrintLevel::Debug, print)));

        let address = address
            .to_socket_addrs()
            .expect("Failed to parse address")
            .next()
            .expect("Failed to parse address");

        let tls_addr = tls.clone().map(|c| c.socket);

        let skel_builder = ProxySkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if tracing::event_enabled!(Level::TRACE) {
            open_skel.progs.process_msg.set_log_level(1);
            open_skel.progs.parse_skb.set_log_level(1);
            open_skel.progs.process_skb.set_log_level(1);
        }

        let mut rodata = open_skel.maps.rodata_data.as_mut().context("rodata")?;
        init_dataplane(config.clone(), &mut rodata)?;

        let tls_port = tls_addr.map(|addr| addr.port()).unwrap_or_default();
        rodata.ip4 = address.try_into_ne_octets()?;
        rodata.port = address.port() as u32;
        rodata.tls_port = tls_port as u32;

        let skel = open_skel.load()?;

        // every program that parses has its own copy of the parser stubs
        let vars = Compiler::new(config.clone()).get_ctx_vars();
        let (mut h1_parsers, mut h2_parsers) = (Vec::new(), Vec::new());
        let progs = [
            (&skel.progs.process_msg, MessageBuffer::Msg),
            (&skel.progs.parse_skb, MessageBuffer::Skb),
            (&skel.progs.process_skb, MessageBuffer::Skb),
        ];
        for (prog, buf) in progs {
            let (parse_h1, parse_h2, get_h2) = match buf {
                MessageBuffer::Msg => ("parse_h1_msg", "parse_h2_msg", "get_h2_match_msg"),
                _ => ("parse_h1_skb", "parse_h2_skb", "get_h2_match_skb"),
            };

            let fd = prog.as_fd().as_raw_fd();
            let Parsers { h1, h2, .. } = new_parsers(&vars)?;
            h1_parsers.push(h1.parse_fn(parse_h1, buf.clone()).attach(fd)?);
            h2_parsers.push(
                h2.parse_fn(parse_h2, buf.clone())
                    .get_fn(get_h2, buf)
                    .attach(fd)?,
            );
        }

        let msg_sock_map_fd = skel.maps.msg_sock_map.as_fd().as_raw_fd();
        skel.progs.process_msg.attach_sockmap(msg_sock_map_fd)?;

        let net_sock_map_fd = skel.maps.net_sock_map.as_fd().as_raw_fd();
        skel.progs
            .accelerate_network
            .attach_sockmap(net_sock_map_fd)?;

        let tls_msg_sock_map_fd = skel.maps.tls_msg_sock_map.as_fd().as_raw_fd();
        skel.progs.remove_tls.attach_sockmap(tls_msg_sock_map_fd)?;

        let skb_sock_map_fd = skel.maps.skb_sock_map.as_fd().as_raw_fd();
        skel.progs.parse_skb.attach_sockmap(skb_sock_map_fd)?;
        skel.progs.process_skb.attach_sockmap(skb_sock_map_fd)?;

        let cgroup_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open("/sys/fs/cgroup")?
            .into_raw_fd();
        let sockops = skel.progs.monitor_sockets.attach_cgroup(cgroup_fd)?;

        let crypto = &skel.progs.crypto_setup;
        let input = libbpf_rs::ProgramInput::default();

        let res = crypto.test_run(input)?;
        if res.return_value != 0 {
            let err = std::io::Error::from_raw_os_error(res.return_value as i32);
            bail!("Crypto setup failed {:?}", err);
        }

        debug!("Crypto setup successful");

        Ok(Self {
            address,
            tls,
            config,
            skel,
            sockops,
            parsers: (h1_parsers, Arc::new(h2_parsers)),
            h1_upstream_pool: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn new_tls_acceptor(&self) -> Result<TlsAcceptor> {
        let Some(ref tls) = self.tls else {
            bail!("TLS configuration not provided");
        };

        let certs = CertificateDer::pem_file_iter(&tls.cert)
            .context("failed to read PEM from certificate chain file")?
            .collect::<Result<Vec<_>, _>>()
            .context("invalid PEM-encoded certificate")?;

        let cert = certs.first().context("no certificate found")?;
        let key = PrivateKeyDer::from_pem_file(&tls.key)
            .context("failed to read PEM from private key file")?;

        let cipher_suite = KtlsCipherSuite {
            version: KtlsVersion::TLS12,
            typ: KtlsCipherType::AesGcm128,
        };

        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites.clear();
        provider
            .cipher_suites
            .push(cipher_suite.as_supported_cipher_suite());

        let mut server_config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[cipher_suite.version.as_supported_version()])?
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)?;
        server_config.enable_secret_extraction = true;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }

    pub async fn listen(self) -> Result<()> {
        let fib = self.get_upstream_fib()?;

        let addrs = self.config.hosts.iter().flat_map(|h| h.instances.clone());

        for addr in addrs {
            trace!("Adding pqueue for {}", addr);
            let addr = addr_key::try_from(&addr)?;
            add_pqueue_to_fib(&fib, fib_key { addr, sk_msg: 0 })?;
            add_pqueue_to_fib(&fib, fib_key { addr, sk_msg: 1 })?;
        }

        if let Some(proxy) = self.config.proxy {
            trace!("Adding pqueue for {}", proxy);
            let proxy_addr = addr_key::try_from(&proxy)?;
            add_pqueue_to_fib(
                &fib,
                fib_key {
                    addr: proxy_addr,
                    sk_msg: 0,
                },
            )?;
            add_pqueue_to_fib(
                &fib,
                fib_key {
                    addr: proxy_addr,
                    sk_msg: 1,
                },
            )?;
        }

        if let Some(ref tls) = self.config.tls {
            trace!("Adding pqueue for {}", tls.socket);
            let tls_addr = addr_key::try_from(&tls.socket)?;
            add_pqueue_to_fib(
                &fib,
                fib_key {
                    addr: tls_addr,
                    sk_msg: 0,
                },
            )?;
            add_pqueue_to_fib(
                &fib,
                fib_key {
                    addr: tls_addr,
                    sk_msg: 1,
                },
            )?;
        }

        let profile = env::var("BPF_PROFILE").unwrap_or("0".to_string());
        let stats = self.config.stats;

        let this = Arc::new(&self);
        tokio::spawn(unsafe {
            let this = std::mem::transmute::<Arc<&Proxy>, Arc<&'static Proxy>>(this);
            async move {
                let mut sigterm = signal(SignalKind::terminate()).unwrap();
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = sigterm.recv() => {},
                }

                if profile == "1" || profile == "true" {
                    info!("Profile stats printed to the eBPF tracelog");
                    this.clone().print_profile_stats().await;
                }
                if stats {
                    this.print_traffic_stats().await;
                }
                exit(0)
            }
        });

        fn listen(addr: SocketAddr) -> Result<TcpListener> {
            let socket = TcpSocket::new_v4()?;
            socket.set_reuseaddr(true)?;
            socket.bind(addr)?;
            let listener = socket.listen(8192)?;
            Ok(listener)
        }

        let plain_addr = self.address;
        let plain_listener = listen(plain_addr)?;
        info!("Listening on {}", plain_addr);

        let tls: Option<(TcpListener, TlsAcceptor)> = if let Some(ref tls) = self.tls {
            let tls_listener = listen(tls.socket)?;
            let tls_acceptor = self.new_tls_acceptor()?;

            info!("Listening for TLS on {}", tls.socket);

            Some((tls_listener, tls_acceptor))
        } else {
            None
        };

        loop {
            if let Some((tls_listener, tls_acceptor)) = &tls {
                tokio::select! {
                    res = self.accept_tls(&tls_listener, &tls_acceptor) => if let Err(e) = res {
                        error!("Error handling TLS downstream connection: {:?}", e);
                    },
                    res = self.accept_plain(&plain_listener) => if let Err(e) = res {
                        error!("Error handling downstream connection: {:?}", e);
                    }
                };
            } else {
                if let Err(e) = self.accept_plain(&plain_listener).await {
                    error!("Error handling downstream connection: {:?}", e);
                };
            }
        }
    }

    async fn print_profile_stats(self: Arc<&Self>) {
        let print = &self.skel.progs.print_profile_stats;
        let input = libbpf_rs::ProgramInput::default();

        match print.test_run(input) {
            Ok(res) => {
                if res.return_value != 0 {
                    let err = std::io::Error::from_raw_os_error(res.return_value as i32);
                    error!("Failed to print profile stats: {:?}", err);
                }
            }
            Err(e) => error!("Failed to call eBPF print_profile_stats: {:?}", e),
        }
    }

    async fn print_traffic_stats(self: Arc<&Self>) {
        let Ok(map) = self.get_traffic_stats() else {
            error!("Failed to get traffic stats");
            return;
        };
        let collected_in_ebpf = vec![
            "downstream_cx_rx_bytes_total",
            "downstream_cx_tx_bytes_total",
            "downstream_rq_total",
            "downstream_rq_1xx",
            "downstream_rq_2xx",
            "downstream_rq_3xx",
            "downstream_rq_4xx",
            "downstream_rq_5xx",
            "http_rbac_allowed",
            "http_rbac_denied",
        ];

        let mut stats = String::new();
        for (idx, key) in collected_in_ebpf.iter().enumerate() {
            let val: Result<Option<u64>> = map.lookup_as(&(idx as u32), MapFlags::empty());
            match val {
                Ok(Some(value)) => {
                    stats.push_str(&format!("{}: {}\n", key, value));
                }
                Ok(None) => {
                    error!("{}: Not found", key);
                }
                Err(e) => {
                    error!("Failed to lookup {:?}: {:?}", key, e);
                }
            }
        }

        info!("Traffic Stats:\n{}", stats.trim());
    }

    async fn accept_plain(&self, listener: &TcpListener) -> Result<()> {
        let (stream, ds_remote_addr) = listener.accept().await?;
        let ds_local_addr = stream.local_addr()?;

        debug!(
            "Accepting connection from {} to {}",
            ds_local_addr, ds_remote_addr,
        );

        self.handle_downstream(stream, ds_local_addr, ds_remote_addr, false)?;

        Ok(())
    }

    async fn accept_tls(&self, listener: &TcpListener, acceptor: &TlsAcceptor) -> Result<()> {
        let (stream, ds_remote_addr) = listener.accept().await?;
        let fd = stream.as_raw_fd();
        let ds_local_addr = stream.local_addr()?;

        debug!(
            "Accepting TLS connection from {} to {}",
            ds_local_addr, ds_remote_addr
        );

        let stream = CorkStream::new(stream);
        let stream = acceptor.accept(stream).await?;
        debug!("Completed TLS handshake");

        let ds_remote_addr_key = sock_key::try_from((&ds_remote_addr, &ds_local_addr)).unwrap();
        update_map(&self.skel.maps.skb_sock_map, &ds_remote_addr_key, &fd)?;

        let stream = ktls::config_ktls_server(stream).await?;
        debug!("Configured kTLS");

        self.handle_downstream(stream, ds_local_addr, ds_remote_addr, true)?;

        Ok(())
    }

    fn handle_downstream<S>(
        &self,
        downstream: S,
        ds_local_addr: SocketAddr,
        ds_remote_addr: SocketAddr,
        tls: bool,
    ) -> Result<()>
    where
        S: AsyncReadExt + AsyncWriteExt + std::marker::Unpin + std::marker::Send + 'static,
    {
        let host = self.config.hosts.iter().find(|h| {
            h.instances
                .iter()
                .find(|a| a.ip() == ds_remote_addr.ip())
                .is_some()
        });
        let http2 = host.map(|h| h.http2).unwrap_or(false);

        if http2 {
            trace!(
                "Connection to {} will be handled with HTTP/2",
                ds_remote_addr
            );
            return self.handle_h2_downstream(downstream, ds_local_addr, ds_remote_addr, tls);
        } else {
            trace!(
                "Connection to {} will be handled with HTTP/1.1",
                ds_remote_addr
            );
            return self.handle_h1_downstream(downstream, ds_local_addr, ds_remote_addr, tls);
        }
    }

    fn handle_h1_downstream<S>(
        &self,
        mut downstream: S,
        ds_local_addr: SocketAddr,
        ds_remote_addr: SocketAddr,
        tls: bool,
    ) -> Result<()>
    where
        S: AsyncReadExt + AsyncWriteExt + std::marker::Unpin + std::marker::Send + 'static,
    {
        let utrn_wait_list = self.get_utrn_wait_list()?;
        let sock_map_wait_list = self.get_sock_map_wait_list()?;
        let fib_downstream = self.get_downstream_fib()?;

        let h1_upstream_pool = self.h1_upstream_pool.clone();
        let h2_parsers = self.parsers.1.clone();
        let ds_remote_addr_key = sock_key::try_from((&ds_remote_addr, &ds_local_addr)).unwrap();

        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(8192);
            let mut upstreams = Vec::new();

            let send_error = async |stream: &mut S| {
                warn!("Sending 500 to {:?}", ds_remote_addr);
                stream
                    .write_all(b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .ok();
            };

            let res = loop {
                match downstream.read_buf(&mut buf).await {
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(0) => {
                        trace!("Connection to {:?} closed", ds_remote_addr);
                        break Ok(());
                    }
                    Ok(len) => len,
                };

                trace!(
                    "Received request: {}",
                    String::from_utf8_lossy(&buf).escape_debug()
                );

                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut req = httparse::Request::new(&mut headers);

                let Ok(hdr_len) = req.parse(&buf) else {
                    warn!(
                        "Failed to parse HTTP request: {}",
                        String::from_utf8_lossy(&buf).escape_debug()
                    );
                    buf.clear();
                    send_error(&mut downstream).await;
                    continue;
                };

                let con_len = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);

                let hdr_len = match hdr_len {
                    httparse::Status::Complete(len) => len,
                    httparse::Status::Partial => continue,
                };

                let req_len = hdr_len + con_len;
                if buf.len() < req_len {
                    debug!("Request not fully read: {}/{}", buf.len(), req_len);
                    continue;
                }

                // check if there is a forwarding token in the waiting list
                let stream_key = data_stream {
                    conn: ds_remote_addr_key,
                    stream_id: 0,
                };
                let us_remote_addr: Option<addr_key> = utrn_wait_list
                    .lookup_and_delete_as(&stream_key)
                    .expect("Failed to lookup utrn_wait_list");

                let (ds_remote_addr_key, us_remote_addr) = if us_remote_addr.is_none() {
                    let gw_ip = match ds_local_addr.ip() {
                        IpAddr::V4(ip) => get_gw_ip(ip),
                        _ => panic!("Unexpected IP version"),
                    };
                    let ds_gw_addr =
                        SocketAddr::V4(SocketAddrV4::new(gw_ip, ds_remote_addr.port()));
                    let ds_remote_addr_key =
                        sock_key::try_from((&ds_gw_addr, &ds_local_addr)).unwrap();

                    let stream_key = data_stream {
                        conn: ds_remote_addr_key,
                        stream_id: 0,
                    };
                    let us_remote_addr: Option<addr_key> = utrn_wait_list
                        .lookup_and_delete_as(&stream_key)
                        .expect("Failed to lookup utrn_wait_list");

                    (ds_remote_addr_key, us_remote_addr)
                } else {
                    (ds_remote_addr_key, us_remote_addr)
                };

                let Some(us_remote_addr) = us_remote_addr else {
                    warn!(
                        "No address found in wait list for downstream connection: {:?}",
                        &ds_remote_addr,
                    );
                    buf.clear();
                    send_error(&mut downstream).await;
                    continue;
                };

                let us_remote_addr: SocketAddr = us_remote_addr.into();
                debug!("Opening upstream connection to {}", us_remote_addr);

                let socket = TcpSocket::new_v4().unwrap();
                socket.set_reuseaddr(true).unwrap();
                let gw_ip = match us_remote_addr.ip() {
                    IpAddr::V4(ip) => get_gw_ip(ip),
                    _ => panic!("Unexpected IP version"),
                };
                let us_local_addr = SocketAddr::V4(SocketAddrV4::new(gw_ip, 0));
                let us_local_addr = match socket.bind(us_local_addr) {
                    Ok(_) => socket.local_addr().unwrap(),
                    Err(e) => {
                        warn!("Failed to bind socket: {}", e);
                        buf.clear();
                        send_error(&mut downstream).await;
                        continue;
                    }
                };

                let us_sock_key = if tls {
                    sock_key::try_from((&us_local_addr, &us_remote_addr)).unwrap()
                } else {
                    sock_key::try_from((&us_remote_addr, &us_local_addr)).unwrap()
                };
                update_map(&sock_map_wait_list, &us_sock_key, &(!tls as u32))
                    .expect("Failed to insert into sock_map_wait_list");

                debug!("Bound socket to {}", us_local_addr);

                let mut upstream = match socket.connect(us_remote_addr).await {
                    Ok(upstream) => upstream,
                    Err(err) => {
                        warn!(
                            "Failed to connect from {} to {}: {}",
                            us_local_addr, us_remote_addr, err
                        );
                        buf.clear();
                        send_error(&mut downstream).await;
                        continue;
                    }
                };

                let us_local_addr_key = addr_key::try_from(&us_local_addr).unwrap();
                debug!(
                    "Opened upstream connection: [{} -> {}]",
                    us_local_addr, us_remote_addr
                );

                update_map(&fib_downstream, &us_local_addr_key, &ds_remote_addr_key)
                    .expect("Failed to insert into FIB");

                let msg = buf.drain(..req_len).collect::<Vec<u8>>();
                let mut req_buf = Cursor::new(&msg);
                if upstream.write_all_buf(&mut req_buf).await.is_err() {
                    buf.clear();
                    send_error(&mut downstream).await;
                    continue;
                }

                // upstream connections are automatically reused by the eBPF program
                // adding them to this shared vector allows us to keep them alive
                upstreams.push(upstream);
            };

            if let Err(e) = res {
                error!("Error handling downstream connection: {:?}", e);
            }

            // the connection can carry HTTP/2 after a preface upgrade
            forget_conn(&h2_parsers, ds_local_addr, ds_remote_addr);

            let mut h1_upstream_pool = h1_upstream_pool.lock().await;
            h1_upstream_pool.extend(upstreams.into_iter());
        });

        Ok(())
    }

    fn handle_h2_downstream<S>(
        &self,
        downstream: S,
        ds_local_addr: SocketAddr,
        ds_remote_addr: SocketAddr,
        tls: bool,
    ) -> Result<()>
    where
        S: AsyncReadExt + AsyncWriteExt + std::marker::Unpin + std::marker::Send + 'static,
    {
        let utrn_wait_list = Arc::new(Mutex::new(self.get_utrn_wait_list()?));
        let sock_map_wait_list = Arc::new(Mutex::new(self.get_sock_map_wait_list()?));
        let h2_conns = Arc::new(Mutex::new(self.get_h2_conns()?));
        let h2_streams = Arc::new(Mutex::new(self.get_h2_streams()?));
        let fib_downstream = Arc::new(Mutex::new(self.get_downstream_fib()?));
        let ds_remote_addr_key = sock_key::try_from((&ds_remote_addr, &ds_local_addr)).unwrap();

        // beeline does not support flow control
        let max_window_size = (1 << 31) - 1;
        let h2_parsers = self.parsers.1.clone();

        tokio::spawn(async move {
            let mut downstream_conn = server::Builder::new()
                .initial_window_size(max_window_size)
                .initial_connection_window_size(max_window_size)
                .max_concurrent_streams(1000000)
                .max_local_error_reset_streams(None)
                .handshake::<_, Bytes>(downstream)
                .await
                .unwrap();

            while let Some(reqres) = downstream_conn.accept().await {
                let (request, mut respond) = match reqres {
                    Ok((request, respond)) => (request, respond),
                    Err(err) => {
                        warn!(
                            "Error accepting request: {:?} from {:?}",
                            err, ds_remote_addr
                        );
                        break;
                    }
                };

                let utrn_wait_list = utrn_wait_list.clone();
                let h2_parsers = h2_parsers.clone();
                let sock_map_wait_list = sock_map_wait_list.clone();
                let h2_conns = h2_conns.clone();
                let h2_streams = h2_streams.clone();
                let fib_downstream = fib_downstream.clone();

                tokio::spawn(async move {
                    debug!("Received request: {:?} from {:?}", request, ds_remote_addr);

                    let utrn_wait_list = utrn_wait_list.lock().await;
                    let sock_map_wait_list = sock_map_wait_list.lock().await;
                    let h2_conns = h2_conns.lock().await;
                    let h2_streams = h2_streams.lock().await;
                    let fib_downstream_ = fib_downstream.lock().await;

                    let mut send_error = || {
                        let mut response = Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/grpc")
                            .body(())
                            .unwrap();

                        for val in response.headers_mut().values_mut() {
                            val.set_sensitive(true);
                        }

                        let mut send_stream = match respond.send_response(response, false) {
                            Ok(stream) => stream,
                            Err(e) => {
                                error!("Failed to send response: {:?}", e);
                                return;
                            }
                        };

                        let mut trailers = http::HeaderMap::new();
                        trailers.insert("grpc-status", "2".parse().unwrap()); // UNKNOWN
                        trailers.insert(
                            "grpc-message",
                            "Failed to connect to upstream".parse().unwrap(),
                        );

                        for val in trailers.values_mut() {
                            val.set_sensitive(true);
                        }

                        if let Err(e) = send_stream.send_trailers(trailers) {
                            error!("Failed to send trailers: {:?}", e);
                        }
                    };

                    // check if there is a forwarding token in the waiting list
                    let stream_id = request.body().stream_id().as_u32();
                    let stream_key = data_stream {
                        conn: ds_remote_addr_key,
                        stream_id,
                    };
                    let us_remote_addr: Option<addr_key> = utrn_wait_list
                        .lookup_and_delete_as(&stream_key)
                        .expect("Failed to lookup utrn_wait_list");

                    let (ds_remote_addr_key, us_remote_addr) = if us_remote_addr.is_none() {
                        let gw_ip = match ds_local_addr.ip() {
                            IpAddr::V4(ip) => get_gw_ip(ip),
                            _ => panic!("Unexpected IP version"),
                        };
                        let ds_gw_addr =
                            SocketAddr::V4(SocketAddrV4::new(gw_ip, ds_remote_addr.port()));
                        let ds_remote_addr_key =
                            sock_key::try_from((&ds_gw_addr, &ds_local_addr)).unwrap();

                        let stream_key = data_stream {
                            conn: ds_remote_addr_key,
                            stream_id,
                        };
                        let us_remote_addr: Option<addr_key> = utrn_wait_list
                            .lookup_and_delete_as(&stream_key)
                            .expect("Failed to lookup utrn_wait_list");

                        (ds_remote_addr_key, us_remote_addr)
                    } else {
                        (ds_remote_addr_key, us_remote_addr)
                    };

                    let Some(us_remote_addr) = us_remote_addr else {
                        warn!(
                            "No address found in wait list for downstream connection: {:?}",
                            &ds_remote_addr,
                        );
                        send_error();
                        return;
                    };

                    let us_remote_addr: SocketAddr = us_remote_addr.into();
                    debug!("Opening upstream connection to {}", us_remote_addr);

                    let socket = TcpSocket::new_v4().unwrap();
                    socket.set_reuseaddr(true).unwrap();
                    let gw_ip = match us_remote_addr.ip() {
                        IpAddr::V4(ip) => get_gw_ip(ip),
                        _ => panic!("Unexpected IP version"),
                    };
                    let us_local_addr = SocketAddr::V4(SocketAddrV4::new(gw_ip, 0));
                    let us_local_addr = match socket.bind(us_local_addr) {
                        Ok(_) => socket.local_addr().unwrap(),
                        Err(e) => {
                            warn!("Failed to bind socket: {}", e);
                            send_error();
                            return;
                        }
                    };

                    let mut us_sock_key =
                        sock_key::try_from((&us_remote_addr, &us_local_addr)).unwrap();
                    if tls {
                        us_sock_key = us_sock_key.invert();
                    }
                    update_map(&*sock_map_wait_list, &us_sock_key, &(!tls as u32))
                        .expect("Failed to insert into sock_map_wait_list");

                    // flag the upstream connection as h2
                    // the downstream connection is flagged by the eBPF program
                    update_map(&*h2_conns, &us_sock_key, &1u32)
                        .expect("Failed to mark connection as h2");

                    let ds_sock_key =
                        sock_key::try_from((&ds_remote_addr, &ds_local_addr)).unwrap();
                    let ds_stream = data_stream {
                        conn: ds_sock_key.clone(),
                        stream_id,
                    };
                    let us_stream = data_stream {
                        conn: us_sock_key.clone(),
                        stream_id: 1,
                    };
                    update_map(&*h2_streams, &ds_stream, &us_stream)
                        .expect("Failed to assign h2 streams");
                    update_map(&*h2_streams, &us_stream, &ds_stream)
                        .expect("Failed to assign h2 streams");

                    debug!("Bound socket to {}", us_local_addr);

                    let upstream = match socket.connect(us_remote_addr).await {
                        Ok(upstream) => upstream,
                        Err(err) => {
                            warn!(
                                "Failed to connect from {} to {}: {}",
                                us_local_addr, us_remote_addr, err
                            );
                            send_error();
                            return;
                        }
                    };

                    let us_local_addr_key = addr_key::try_from(&us_local_addr).unwrap();
                    debug!(
                        "Opened upstream connection: [{} -> {}]",
                        us_local_addr, us_remote_addr
                    );

                    update_map(&*fib_downstream_, &us_local_addr_key, &ds_remote_addr_key)
                        .expect("Failed to insert into FIB");

                    let (client, upstream_conn) = client::Builder::new()
                        .initial_window_size(max_window_size)
                        .initial_connection_window_size(max_window_size)
                        .max_concurrent_streams(1000000)
                        .max_local_error_reset_streams(None)
                        .handshake::<_, Bytes>(upstream)
                        .await
                        .unwrap();

                    tokio::spawn(async move {
                        if let Err(e) = upstream_conn.await {
                            error!(
                                "Error driving HTTP/2 connection on {}: {}",
                                us_local_addr, e
                            );
                        }
                        debug!("Upstream connection closed {}", us_local_addr);
                        forget_conn(&h2_parsers, us_local_addr, us_remote_addr);
                    });

                    let mut client = client.ready().await.unwrap();

                    let (parts, mut body) = request.into_parts();
                    let mut headers = parts.headers.clone();
                    for val in headers.values_mut() {
                        val.set_sensitive(true);
                    }

                    let forward = Request::from_parts(parts, ());

                    let (response, mut stream) =
                        client.send_request(forward, body.is_end_stream()).unwrap();

                    while let Some(Ok(chunk)) = body.data().await {
                        trace!(
                            "Sending data frame (len: {}, end of stream: {})",
                            chunk.len(),
                            body.is_end_stream()
                        );
                        if let Err(e) = stream.send_data(chunk, body.is_end_stream()) {
                            error!("Failed to send data to upstream: {}", e);
                        }
                    }

                    trace!("Sent!");

                    drop(utrn_wait_list);
                    drop(sock_map_wait_list);
                    drop(h2_conns);
                    drop(h2_streams);
                    drop(fib_downstream_);

                    // we have to wait for the response otherwise the stream gets reset
                    let _ = response.await;

                    trace!("Removing upstream connection from FIB");
                    let fib_downstream_ = fib_downstream.lock().await;
                    delete_map(&*fib_downstream_, &us_local_addr_key)
                        .expect("Failed to delete from FIB");
                });
            }

            forget_conn(&h2_parsers, ds_local_addr, ds_remote_addr);
        });

        Ok(())
    }

    fn get_utrn_wait_list(&self) -> Result<MapHandle> {
        let id = self.skel.maps.utrn_wait_list.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
    }

    fn get_upstream_fib(&self) -> Result<MapHandle> {
        let id = self.skel.maps.fib_upstream.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
    }

    fn get_downstream_fib(&self) -> Result<MapHandle> {
        let id = self.skel.maps.fib_downstream.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
    }

    fn get_traffic_stats(&self) -> Result<MapHandle> {
        let id = self.skel.maps.traffic_stats.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
    }

    fn get_sock_map_wait_list(&self) -> Result<MapHandle> {
        let id = self.skel.maps.sock_map_wait_list.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
    }

    fn get_h2_conns(&self) -> Result<MapHandle> {
        let id = self.skel.maps.h2_conns.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
    }

    fn get_h2_streams(&self) -> Result<MapHandle> {
        let id = self.skel.maps.h2_streams.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwt_vars_share_the_authorization_capture() {
        let vars = vec![
            Variable::buffer("preface", "char", Some(24)),
            Variable::range("authorization"),
            Variable::buffer("method", "char", Some(7)),
            Variable::buffer("jwt_claims", "char", Some(4095)),
            Variable::buffer("jwt_sig", "char", Some(63)),
        ];
        let parsers = new_parsers(&vars).unwrap();

        assert_eq!(parsers.h1_mids[0], u8::from(parsers.h1_preface));
        assert_eq!(parsers.h1_mids[3], parsers.h1_mids[1]);
        assert_eq!(parsers.h1_mids[4], parsers.h1_mids[1]);
        assert_ne!(parsers.h1_mids[2], parsers.h1_mids[1]);
        assert_eq!(&parsers.h2_mids[3..], &[NO_MATCH, NO_MATCH]);
        assert_eq!(parsers.h2_mids[0], NO_MATCH);
    }
}
