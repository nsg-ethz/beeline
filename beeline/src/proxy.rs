use crate::bpf::{types::*, TypedLookUp, *};
use ::bytes::Bytes;
use anyhow::{anyhow, bail, ensure, Context, Result};
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
    btf::BtfType,
    query::{LinkInfoIter, LinkTypeInfo, ProgInfoIter, ProgramInfo},
    set_print,
    skel::{OpenSkel, Skel, SkelBuilder},
    AsRawLibbpf, Link, MapCore, MapFlags, MapHandle, MapType, PrintLevel,
};
use libc::exit;
use rustls::{
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    ServerConfig,
};
use std::{
    collections::HashMap,
    env,
    ffi::OsStr,
    io::Cursor,
    mem::MaybeUninit,
    net::{IpAddr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    signal::unix::{signal, Signal, SignalKind},
    sync::{watch, Mutex},
    time::{sleep, Instant},
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

/// The ports this instance owns in the pinned `beeline_owners` map.
///
/// Releasing them removes the entries of this instance and of the ones that are gone,
/// and unpins the map once no instance owns a port anymore, so that it does not outlive
/// beeline. Dropping releases them as well, but `exit` does not drop, so the paths that
/// exit release explicitly.
struct Owners {
    map: MapHandle,
    pin: Option<PathBuf>,
    pid: u32,
}

impl Owners {
    fn new(map: MapHandle, pin: Option<&OsStr>) -> Self {
        Self {
            map,
            pin: pin.map(PathBuf::from),
            pid: std::process::id(),
        }
    }

    fn claim(&self, port: u16) -> Result<()> {
        update_map(&self.map, &(port as u32), &self.pid)
    }

    fn release(&self) {
        for key in self.map.keys().collect::<Vec<_>>() {
            let Ok(Some(val)) = self.map.lookup(&key, MapFlags::ANY) else {
                continue;
            };
            let Ok(pid) = <[u8; 4]>::try_from(val.as_slice()).map(u32::from_ne_bytes) else {
                continue;
            };

            // an instance that was killed could not release its ports
            let gone = unsafe { libc::kill(pid as i32, 0) } < 0
                && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH);
            if pid == self.pid || gone {
                if let Err(e) = self.map.delete(&key) {
                    warn!("Failed to release port of {}: {}", pid, e);
                }
            }
        }

        // a hot restart hands the ports to the new instance before the old one exits,
        // so the map is only empty once the last instance is gone
        if let Some(pin) = &self.pin {
            if self.map.keys().next().is_none() {
                match std::fs::remove_file(pin) {
                    Ok(()) => debug!("Unpinned {}", pin.display()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                    Err(e) => warn!("Failed to unpin {}: {}", pin.display(), e),
                }
            }
        }
    }
}

impl Drop for Owners {
    fn drop(&mut self) {
        self.release();
    }
}

/// The signals that terminate beeline.
///
/// Registering them replaces the default action, which kills the process without
/// releasing its pinned maps. A signal is only delivered to the streams that exist
/// when it arrives, so a caller that registers them before it attaches catches the
/// ones that arrive while the data plane loads.
pub struct Shutdown {
    term: Signal,
    int: Signal,
}

impl Shutdown {
    pub fn register() -> Result<Self> {
        Ok(Self {
            term: signal(SignalKind::terminate())?,
            int: signal(SignalKind::interrupt())?,
        })
    }

    async fn recv(&mut self) {
        tokio::select! {
            _ = self.term.recv() => {},
            _ = self.int.recv() => {},
        }
    }
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

fn boottime() -> Duration {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut ts) };
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

struct ProgStats {
    table: &'static str,
    name: String,
    load: Duration,
    verify: Option<Duration>,
    verified_insns: u32,
    size: Option<usize>,
}

fn verifier_stats(
    skel: &ProxySkel,
    logs: &[(String, Vec<u8>)],
    beeper_stats: &[&beeper::VerifierStats],
    load_ends: &[Duration],
) -> Result<Vec<ProgStats>> {
    let infos: HashMap<u32, ProgramInfo> = ProgInfoIter::default()
        .map(|info| (info.id, info))
        .collect();

    let mut proxy = Vec::new();
    for prog in skel.object().progs() {
        let name = prog.name().to_string_lossy().into_owned();
        let verify_us = logs.iter().find(|(n, _)| *n == name).and_then(|(_, log)| {
            let log = String::from_utf8_lossy(log);
            let us = log.split("verification time ").nth(1)?.split(' ').next()?;
            Some(Duration::from_micros(us.parse().ok()?))
        });
        let id = libbpf_rs::Program::id_from_fd(prog.as_fd())?;
        // libbpf keeps the instructions it handed to the kernel
        proxy.push((name, id, verify_us, Some(prog.insn_cnt())));
    }

    // beeper loads its own objects, they are found by the program they extend
    let btf = skel.object().btf()?.context("proxy BTF")?;
    let mut beeper = Vec::new();
    for link in LinkInfoIter::default() {
        let LinkTypeInfo::Tracing(tracing) = link.info else {
            continue;
        };
        let Some((target, ..)) = proxy
            .iter()
            .find(|(_, id, ..)| *id == tracing.target_obj_id)
        else {
            continue;
        };
        let func = btf
            .type_by_id::<BtfType>(tracing.target_btf_id.into())
            .and_then(|ty| ty.name())
            .unwrap_or_default();
        let info = infos.get(&link.prog_id).context("beeper program info")?;
        let name = format!(
            "{} -> {target}/{}",
            info.name.to_string_lossy(),
            func.to_string_lossy()
        );
        // beeper drops its objects after the load, but kept their stats
        let stats = beeper_stats.iter().find(|s| s.id == link.prog_id);
        beeper.push((
            name,
            link.prog_id,
            stats.and_then(|s| s.verify),
            stats.map(|s| s.size),
        ));
    }

    // the kernel stamps the start of every load, the next stamp ends it
    // ponytail: libbpf's work between two loads counts towards the first one
    let mut marks = load_ends.to_vec();
    for (_, id, ..) in proxy.iter().chain(&beeper) {
        marks.push(infos.get(id).context("program info")?.load_time);
    }
    marks.sort();

    let mut stats = Vec::new();
    for (table, progs) in [("proxy", proxy), ("beeper", beeper)] {
        for (name, id, verify, size) in progs {
            let info = &infos[&id];
            let end = marks.iter().find(|m| **m > info.load_time);
            let load = end.map(|end| *end - info.load_time).unwrap_or_default();
            stats.push(ProgStats {
                table,
                name,
                load,
                verify,
                verified_insns: info.verified_insns,
                size,
            });
        }
    }

    Ok(stats)
}

const DATA_PLANE: &[&str] = &[
    "parse_skb",
    "process_skb",
    "remove_tls",
    "accelerate_network",
    "process_msg",
];
const CONTROL_PLANE: &[&str] = &["monitor_sockets", "crypto_setup", "print_profile_stats"];

fn print_verifier_stats(runs: &[Vec<ProgStats>]) {
    let n = runs.len() as u32;
    let dash = || String::from("-");
    let row = |name: &str, load: &str, verify: &str, insns: &str, size: &str| {
        println!("{name:<48} {load:>12} {verify:>12} {insns:>14} {size:>14}");
    };

    let is_proxy = |p: &ProgStats| p.table == "proxy";
    let known = |p: &ProgStats| {
        p.name.starts_with("verify_")
            || DATA_PLANE.contains(&p.name.as_str())
            || CONTROL_PLANE.contains(&p.name.as_str())
    };
    // the title, which programs belong to it, and whether it ends with a total
    let sections: [(&str, &dyn Fn(&ProgStats) -> bool, bool); 5] = [
        (
            "filters",
            &|p| is_proxy(p) && p.name.starts_with("verify_"),
            false,
        ),
        (
            "data plane",
            &|p| is_proxy(p) && DATA_PLANE.contains(&p.name.as_str()),
            true,
        ),
        (
            "control plane",
            &|p| is_proxy(p) && CONTROL_PLANE.contains(&p.name.as_str()),
            true,
        ),
        // a program that is new to the proxy still shows up
        ("other", &|p| is_proxy(p) && !known(p), true),
        ("beeper", &|p| p.table == "beeper", true),
    ];

    for (title, belongs, with_total) in sections {
        let progs: Vec<usize> = (0..runs[0].len())
            .filter(|&i| belongs(&runs[0][i]))
            .collect();
        if progs.is_empty() {
            continue;
        }

        row(
            title,
            "load (us)",
            "verify (us)",
            "verif (insns)",
            "size (insns)",
        );
        let (mut load_total, mut verify_total) = (Duration::ZERO, Duration::ZERO);
        let (mut insns_total, mut size_total) = (0u64, 0usize);
        for i in progs {
            let prog = &runs[0][i];
            let load = runs.iter().map(|run| run[i].load).sum::<Duration>() / n;
            let verify = runs
                .iter()
                .map(|run| run[i].verify)
                .sum::<Option<Duration>>()
                .map(|v| v / n);
            load_total += load;
            verify_total += verify.unwrap_or_default();
            insns_total += prog.verified_insns as u64;
            size_total += prog.size.unwrap_or_default();
            row(
                &prog.name,
                &load.as_micros().to_string(),
                &verify.map_or_else(dash, |v| v.as_micros().to_string()),
                &prog.verified_insns.to_string(),
                &prog.size.map_or_else(dash, |s| s.to_string()),
            );
        }
        if with_total {
            row(
                "total",
                &load_total.as_micros().to_string(),
                &verify_total.as_micros().to_string(),
                &insns_total.to_string(),
                &size_total.to_string(),
            );
        }
        println!();
    }
    println!("averaged over {n} loads");
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
    stats: Vec<ProgStats>,

    /// How long a drain waits for the open connections to close.
    pub drain_time: Duration,
    /// The pid of the instance that this one replaces. It is told to drain once this one listens.
    pub replace: Option<i32>,
    /// The start of the process, for the startup time that listen prints.
    pub started: std::time::Instant,
    /// The signals that terminate this instance, registered by `listen` unless set.
    pub shutdown: Option<Shutdown>,
    owners: Owners,
    drain: watch::Sender<bool>,
    // every connection task holds a clone, so the strong count is the number of open connections + 1
    conns: Arc<()>,
}

unsafe impl<'obj> Send for Proxy<'obj> {}

unsafe impl<'obj> Sync for Proxy<'obj> {}

impl<'obj> Proxy<'obj> {
    pub fn verify(
        address: SocketAddr,
        tls: Option<TlsConfig>,
        config: Config,
        runs: usize,
    ) -> Result<()> {
        let mut runs_stats: Vec<Vec<ProgStats>> = Vec::new();
        for _ in 0..runs {
            let mut open_obj = MaybeUninit::uninit();
            let mut proxy =
                Proxy::attach(address, tls.clone(), config.clone(), &mut open_obj, true)?;
            let stats = std::mem::take(&mut proxy.stats);
            // the averages pair the programs of every load by their position
            if let Some(first) = runs_stats.first() {
                let same = first
                    .iter()
                    .map(|p| &p.name)
                    .eq(stats.iter().map(|p| &p.name));
                ensure!(same, "the programs differ between loads");
            }
            runs_stats.push(stats);
        }
        print_verifier_stats(&runs_stats);
        Ok(())
    }

    pub fn attach<A: ToSocketAddrs>(
        address: A,
        tls: Option<TlsConfig>,
        config: Config,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
        verify: bool,
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

        // the kernel only logs the verification time on the stats log level
        let mut logs = Vec::new();
        if verify {
            for mut prog in open_skel.open_object_mut().progs_mut() {
                prog.set_autoload(true);
                prog.set_log_level(4);
                // a truncated log fails the load, so the buffer is generous
                let mut log = vec![0u8; 1 << 16];
                unsafe {
                    libbpf_rs::libbpf_sys::bpf_program__set_log_buf(
                        prog.as_libbpf_object().as_ptr(),
                        log.as_mut_ptr().cast(),
                        log.len() as _,
                    );
                }
                logs.push((prog.name().to_string_lossy().into_owned(), log));
            }
        }

        let mut rodata = open_skel.maps.rodata_data.as_mut().context("rodata")?;
        init_dataplane(config.clone(), &mut rodata)?;

        let tls_port = tls_addr.map(|addr| addr.port()).unwrap_or_default();
        rodata.ip4 = address.try_into_ne_octets()?;
        rodata.port = address.port() as u32;
        rodata.tls_port = tls_port as u32;
        rodata.pid = std::process::id();

        let skel = open_skel.load()?;
        // created right away, so that a failure below does not leave the pin behind
        let owners = Owners::new(
            MapHandle::try_from(&skel.maps.beeline_owners)?,
            skel.maps.beeline_owners.get_pin_path(),
        );
        let mut load_ends = vec![boottime()];

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
            let (h1, h2) = if verify {
                (h1.verifier_stats(), h2.verifier_stats())
            } else {
                (h1, h2)
            };
            let h1 = h1.parse_fn(parse_h1, buf.clone());
            let h2 = h2.parse_fn(parse_h2, buf.clone()).get_fn(get_h2, buf);

            h1_parsers.push(h1.attach(fd)?);
            load_ends.push(boottime());
            h2_parsers.push(h2.attach(fd)?);
            load_ends.push(boottime());
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

        let stats = if verify {
            let beeper = h1_parsers
                .iter()
                .flat_map(|p| p.verifier_stats())
                .chain(h2_parsers.iter().flat_map(|p| p.verifier_stats()))
                .collect::<Vec<_>>();
            verifier_stats(&skel, &logs, &beeper, &load_ends)?
        } else {
            Vec::new()
        };

        Ok(Self {
            address,
            tls,
            config,
            skel,
            sockops,
            parsers: (h1_parsers, Arc::new(h2_parsers)),
            h1_upstream_pool: Arc::new(Mutex::new(Vec::new())),
            stats,
            drain_time: Duration::from_secs(600),
            replace: None,
            started: std::time::Instant::now(),
            shutdown: None,
            owners,
            drain: watch::Sender::new(false),
            conns: Arc::new(()),
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

    pub async fn listen(mut self) -> Result<()> {
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
        let mut shutdown = match self.shutdown.take() {
            Some(shutdown) => shutdown,
            None => Shutdown::register()?,
        };

        let this = Arc::new(&self);
        tokio::spawn(unsafe {
            let this = std::mem::transmute::<Arc<&Proxy>, Arc<&'static Proxy>>(this);
            async move {
                shutdown.recv().await;
                info!("Shutting down");

                if profile == "1" || profile == "true" {
                    info!("Profile stats printed to the eBPF tracelog");
                    this.clone().print_profile_stats().await;
                }
                if stats {
                    this.clone().print_traffic_stats().await;
                }
                this.owners.release();
                exit(0)
            }
        });

        fn listen(addr: SocketAddr) -> Result<TcpListener> {
            let socket = TcpSocket::new_v4()?;
            socket.set_reuseaddr(true)?;
            // the instance of a hot reload binds while the old one still listens
            socket.set_reuseport(true)?;
            socket.bind(addr)?;
            let listener = socket.listen(8192)?;
            Ok(listener)
        }

        let plain_addr = self.address;
        let plain_listener = listen(plain_addr)?;
        info!(
            "Listening on {}, in {}ms",
            plain_addr,
            self.started.elapsed().as_millis()
        );

        let tls: Option<(TcpListener, TlsAcceptor)> = if let Some(ref tls) = self.tls {
            let tls_listener = listen(tls.socket)?;
            let tls_acceptor = self.new_tls_acceptor()?;

            info!("Listening for TLS on {}", tls.socket);

            Some((tls_listener, tls_acceptor))
        } else {
            None
        };

        let mut ports = vec![plain_addr.port()];
        ports.extend(self.tls.as_ref().map(|t| t.socket.port()));
        for port in ports {
            self.owners.claim(port)?;
        }

        // ponytail: connections that complete their handshake between the owner update
        // above and the moment the old instance closes its listener can get the BPF state
        // of one instance and the accept of the other. An SK_REUSEPORT program that reads
        // beeline_owners would steer them at SYN time.
        if let Some(pid) = self.replace {
            if unsafe { libc::kill(pid, libc::SIGUSR1) } < 0 {
                warn!(
                    "Failed to signal {}: {}",
                    pid,
                    std::io::Error::last_os_error()
                );
            }
        }

        let mut drain = signal(SignalKind::user_defined1())?;
        loop {
            let accept_tls = async {
                let Some((listener, acceptor)) = &tls else {
                    return std::future::pending().await;
                };
                self.accept_tls(listener, acceptor).await
            };

            tokio::select! {
                _ = drain.recv() => break,
                res = accept_tls => if let Err(e) = res {
                    error!("Error handling TLS downstream connection: {:?}", e);
                },
                res = self.accept_plain(&plain_listener) => if let Err(e) = res {
                    error!("Error handling downstream connection: {:?}", e);
                },
            }
        }

        // with net.ipv4.tcp_migrate_req=1, the kernel moves the accept queue to the new instance
        drop(plain_listener);
        drop(tls);
        self.drain.send_replace(true);

        let deadline = Instant::now() + self.drain_time;
        info!(
            "Draining {} connections",
            Arc::strong_count(&self.conns) - 1
        );
        while Arc::strong_count(&self.conns) > 1 && Instant::now() < deadline {
            sleep(Duration::from_millis(100)).await;
        }
        info!(
            "Drained, closing {} connections",
            Arc::strong_count(&self.conns) - 1
        );

        if stats {
            Arc::new(&self).print_traffic_stats().await;
        }
        // the new instance owns the ports by now, so this only unpins if it is gone too
        self.owners.release();
        std::process::exit(0)
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
        let conn = self.conns.clone();

        tokio::spawn(async move {
            let _conn = conn;
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
        let conn = self.conns.clone();
        let mut drain = self.drain.subscribe();

        tokio::spawn(async move {
            let _conn = conn;
            let mut downstream_conn = server::Builder::new()
                .initial_window_size(max_window_size)
                .initial_connection_window_size(max_window_size)
                .max_concurrent_streams(1000000)
                .max_local_error_reset_streams(None)
                .handshake::<_, Bytes>(downstream)
                .await
                .unwrap();

            let mut draining = false;
            loop {
                let reqres = tokio::select! {
                    reqres = downstream_conn.accept() => reqres,
                    _ = drain.wait_for(|d| *d), if !draining => {
                        draining = true;
                        // sends GOAWAY, accept returns None once the open streams are done
                        downstream_conn.graceful_shutdown();
                        continue;
                    }
                };
                let Some(reqres) = reqres else { break };
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
                        // the eBPF program hands the header blocks of the responses on this
                        // connection to whichever downstream connection the stream came from,
                        // each with HPACK state of its own. Without a dynamic table, a block
                        // refers to nothing an earlier one on this connection put there
                        .header_table_size(0)
                        .handshake::<_, Bytes>(upstream)
                        .await
                        .unwrap();
                    trace!("Upstream handshake done on {}", us_local_addr);

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
                    trace!("Upstream connection {} ready", us_local_addr);

                    let (parts, mut body) = request.into_parts();
                    let mut headers = parts.headers.clone();
                    for val in headers.values_mut() {
                        val.set_sensitive(true);
                    }

                    let forward = Request::from_parts(parts, ());

                    // the streams are only assigned once the whole request has been read.
                    // From then on, the eBPF program redirects the frames of the downstream
                    // stream to the upstream connection itself, so a frame of the body that
                    // arrives later never reaches this task, which then waits for it forever
                    let mut chunks = Vec::new();
                    while let Some(Ok(chunk)) = body.data().await {
                        chunks.push(chunk);
                    }
                    trace!(
                        "Read the request body of stream {} in {} chunk(s)",
                        stream_id,
                        chunks.len()
                    );

                    // before the request goes out, its response could get here first otherwise
                    update_map(&*h2_streams, &ds_stream, &us_stream)
                        .expect("Failed to assign h2 streams");
                    update_map(&*h2_streams, &us_stream, &ds_stream)
                        .expect("Failed to assign h2 streams");

                    let (response, mut stream) =
                        client.send_request(forward, chunks.is_empty()).unwrap();

                    let last = chunks.len();
                    for (i, chunk) in chunks.into_iter().enumerate() {
                        let end_of_stream = i + 1 == last;
                        trace!(
                            "Sending data frame (len: {}, end of stream: {})",
                            chunk.len(),
                            end_of_stream
                        );
                        if let Err(e) = stream.send_data(chunk, end_of_stream) {
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
