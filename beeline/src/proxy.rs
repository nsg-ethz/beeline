use crate::{
    bpf::{types::*, TypedLookUp, *},
    parse::{http::HttpParser, Action},
};
use anyhow::{anyhow, bail, Result};
use as_bytes::AsBytes;
use common::{
    config::beeline::Config,
    net::{get_gw_ip, TryIntoRawOctets},
    Compiler,
};
use ktls::{CorkStream, KtlsCipherSuite, KtlsCipherType, KtlsVersion};
use libbpf_rs::{
    set_print,
    skel::{OpenSkel, SkelBuilder},
    Link, MapCore, MapFlags, MapHandle, MapType, PrintLevel,
};
use libc::exit;
use rcgen::generate_simple_self_signed;
use rustls::ServerConfig;
use std::{
    env,
    io::Cursor,
    mem::MaybeUninit,
    net::{IpAddr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
    sync::{Arc, Mutex},
};
use tokio::{
    io::{self, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    signal::unix::{signal, SignalKind},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, trace, warn, Level};

pub mod bpf;
pub mod parse;

fn new_transition(state: u16, action: Action, rodata: &rodata) -> trans {
    let action = match action {
        Action::StartCapture(mid) => rodata.a_start_capture | (mid as u16) & rodata.a_id_mask,
        Action::EndCapture(cid, mid) => {
            let id = (cid as u16) << 6 | (mid as u16);
            rodata.a_end_capture | id & rodata.a_id_mask
        }
        Action::Done => rodata.a_done,
        Action::None => 0,
    };

    trans { state, action }
}

fn inject_parser(parser: HttpParser, skel: &mut OpenProxySkel) -> Result<()> {
    for (from, to, input, action) in parser.iter_transitions() {
        let s = *from as usize;
        let t = new_transition(*to, *action, skel.maps.rodata_data);
        skel.maps.rodata_data.s2ts[s][*input as usize] = t;
    }

    Ok(())
}

fn add_pqueue_to_fib<M: MapCore>(map: &M, addr: addr_key) -> Result<()> {
    let key = unsafe { addr.as_bytes() };
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
    pub tls_port: Option<u16>,
    pub config: Config,

    skel: ProxySkel<'obj>,
    #[allow(dead_code)]
    sockops: Link,

    upstream_pool: Arc<Mutex<Vec<TcpStream>>>,
}

unsafe impl<'obj> Send for Proxy<'obj> {}

unsafe impl<'obj> Sync for Proxy<'obj> {}

impl<'obj> Proxy<'obj> {
    pub fn attach<A: ToSocketAddrs>(
        address: A,
        tls_port: Option<u16>,
        config: Config,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        set_print(Some((PrintLevel::Debug, print)));

        let address = address
            .to_socket_addrs()?
            .next()
            .expect("Failed to parse address");

        let skel_builder = ProxySkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if tracing::event_enabled!(Level::DEBUG) {
            open_skel.progs.msg_verdict.set_log_level(1);
        }

        let compiler = Compiler::new(config.clone());
        let vars = compiler.get_ctx_vars();

        let mut parser = HttpParser::new(
            open_skel.maps.rodata_data.s_init,
            open_skel.maps.rodata_data.s_any,
        );

        for hdr in vars.iter() {
            match hdr.name() {
                "method" => parser.match_http_req_status_line()?,
                "path" => (),
                "status_code" => parser.match_http_status_code()?,
                "jwt_claims" => parser.match_http_hdr_auth()?,
                "jwt_sig" => (),
                name => parser.match_http_hdr(name)?,
            }
        }

        // this is necessary so that the DFA won't
        // parse beyond the HTTP header
        parser.done_on_http_hdr_end()?;

        if parser.num_captures() >= 31 {
            bail!("Parsing too many patterns.")
        }

        info!("Injecting HTTP parser with {} states", parser.num_states());
        inject_parser(parser, &mut open_skel)?;

        if let Some(network) = &config.network {
            let addr_raw = network.addr.try_into_ne_octets()?;
            open_skel.maps.rodata_data.ip4_start = addr_raw;
            open_skel.maps.rodata_data.ip4_end = addr_raw + network.len();

            let gw_raw = get_gw_ip(network.addr).try_into_ne_octets()?;
            open_skel.maps.rodata_data.gw = gw_raw;
        }

        open_skel.maps.rodata_data.ip4 = address.try_into_ne_octets()?;
        open_skel.maps.rodata_data.port = address.port() as u32;
        open_skel.maps.rodata_data.tls_port = tls_port.unwrap_or_default() as u32;

        let skel = open_skel.load()?;

        let sock_map_fd = skel.maps.sock_map.as_fd().as_raw_fd();
        skel.progs.msg_verdict.attach_sockmap(sock_map_fd)?;

        let egress_fd = skel.maps.egress.as_fd().as_raw_fd();
        skel.progs.skb_parser.attach_sockmap(egress_fd)?;
        skel.progs.skb_verdict.attach_sockmap(egress_fd)?;

        let cgroup_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open("/sys/fs/cgroup")?
            .into_raw_fd();
        let sockops = skel.progs.monitor_sockets.attach_cgroup(cgroup_fd)?;

        // let crypto = &skel.progs.crypto_setup;
        // let input = libbpf_rs::ProgramInput::default();

        // let res = crypto.test_run(input)?;
        // if res.return_value != 0 {
        //     let err = std::io::Error::from_raw_os_error(res.return_value as i32);
        //     bail!("Crypto setup failed {:?}", err);
        // }

        // debug!("Crypto setup successful");

        Ok(Self {
            address,
            tls_port,
            config,
            skel,
            sockops,
            upstream_pool: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn new_tls_acceptor(&self) -> Result<TlsAcceptor> {
        let mut subject_alt_names = vec![self.address.ip().to_string()];
        if self.address.ip().is_loopback() {
            subject_alt_names.push("localhost".to_string());
        }

        let ckey = generate_simple_self_signed(subject_alt_names)?;

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
            .with_single_cert(
                vec![ckey.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(ckey.signing_key.serialize_der())
                    .into(),
            )?;
        server_config.enable_secret_extraction = true;
        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }

    pub async fn listen(self) -> Result<()> {
        let fib = self.get_upstream_fib()?;

        let addrs = self
            .config
            .hosts
            .iter()
            .flat_map(|h| h.instances.clone())
            .map(|a| addr_key::try_from(&a))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_default();

        for addr in addrs {
            add_pqueue_to_fib(&fib, addr)?;
        }

        if let Some(proxy) = self.config.proxy {
            let proxy_addr = addr_key::try_from(&proxy)?;
            add_pqueue_to_fib(&fib, proxy_addr)?;
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

        let tls: Option<(TcpListener, TlsAcceptor)> = if let Some(port) = self.tls_port {
            let tls_addr = SocketAddr::new(plain_addr.ip(), port);
            let tls_listener = listen(tls_addr)?;
            let tls_acceptor = self.new_tls_acceptor()?;

            info!("Listening for TLS on {}", tls_addr);

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
            ds_local_addr, ds_remote_addr
        );

        self.handle_downstream(stream, ds_local_addr, ds_remote_addr)?;

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
        update_map(&self.skel.maps.egress, &ds_remote_addr_key, &fd)?;

        let stream = ktls::config_ktls_server(stream).await?;
        debug!("Configured kTLS");

        self.handle_downstream(stream, ds_local_addr, ds_remote_addr)?;

        Ok(())
    }

    fn handle_downstream<S>(
        &self,
        mut downstream: S,
        ds_local_addr: SocketAddr,
        ds_remote_addr: SocketAddr,
    ) -> Result<()>
    where
        S: AsyncReadExt + AsyncWriteExt + std::marker::Unpin + std::marker::Send + 'static,
    {
        let utrn_wait_list = self.get_utrn_wait_list()?;
        let sock_map_wait_list = self.get_sock_map_wait_list()?;
        let fib_downstream = self.get_downstream_fib()?;

        let upstream_pool = self.upstream_pool.clone();
        let ds_remote_addr_key = sock_key::try_from((&ds_remote_addr, &ds_local_addr)).unwrap();
        let use_skmsg = ds_local_addr.ip().is_loopback();

        tokio::spawn(async move {
            let mut buf = Vec::with_capacity(8192);
            let mut upstreams = Vec::new();

            let send_error = async |stream: &mut S| {
                error!("Sending 500 to {:?}", ds_remote_addr);
                stream
                    .write_all(b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\n\r\n")
                    .await
                    .ok();
            };

            let res = loop {
                match downstream.read_buf(&mut buf).await {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
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
                let hdr_len = req.parse(&buf).expect("Failed to parse HTTP request");

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
                let us_remote_addr: Option<addr_key> = utrn_wait_list
                    .lookup_and_delete_as(&ds_remote_addr_key)
                    .expect("Failed to lookup utrn_wait_list");

                let Some(us_remote_addr) = us_remote_addr else {
                    warn!(
                        "No address found in wait list for downstream connection: {:?}",
                        &ds_remote_addr,
                    );
                    send_error(&mut downstream).await;
                    continue;
                };

                let us_remote_addr: SocketAddr = us_remote_addr.into();
                debug!("Opening upstream connection to {}", us_remote_addr);

                let socket = TcpSocket::new_v4().unwrap();
                let gw_ip = match us_remote_addr.ip() {
                    IpAddr::V4(ip) => get_gw_ip(ip),
                    _ => panic!("Unexpected IP version"),
                };
                let us_local_addr = SocketAddr::V4(SocketAddrV4::new(gw_ip, 0));
                match socket.bind(us_local_addr) {
                    Ok(_) => (),
                    Err(e) => {
                        error!("Failed to bind socket: {}", e);
                        continue;
                    }
                }

                let us_local_addr = socket.local_addr().unwrap();
                let us_sock_key = if use_skmsg {
                    sock_key::try_from((&us_remote_addr, &us_local_addr)).unwrap()
                } else {
                    sock_key::try_from((&us_local_addr, &us_remote_addr)).unwrap()
                };
                update_map(&sock_map_wait_list, &us_sock_key, &(use_skmsg as u32))
                    .expect("Failed to insert into sock_map_wait_list");

                debug!("Bound socket to {}", us_local_addr);

                let Ok(mut upstream) = socket.connect(us_remote_addr).await else {
                    send_error(&mut downstream).await;
                    continue;
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

            let mut upstream_pool = upstream_pool.lock().unwrap();
            upstream_pool.extend(upstreams.into_iter());
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

    fn get_sock_map(&self) -> Result<MapHandle> {
        let id = self.skel.maps.sock_map.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
    }

    fn get_sock_map_wait_list(&self) -> Result<MapHandle> {
        let id = self.skel.maps.sock_map_wait_list.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
    }
}
