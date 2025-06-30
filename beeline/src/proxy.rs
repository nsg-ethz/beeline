use crate::{
    bpf::{types::*, TypedLookUp, *},
    parse::{http::HttpParser, Action},
};
use anyhow::{anyhow, bail, Result};
use as_bytes::AsBytes;
use common::{
    net::{SocketBinder, TryIntoRawOctets},
    Config,
};
use libbpf_rs::{
    set_print,
    skel::{OpenSkel, SkelBuilder},
    Link, MapCore, MapFlags, MapHandle, MapType, PrintLevel,
};
use libc::exit;
use log::{debug, error, info, log_enabled, trace, warn};
use ma::{NewUpstream, Pipeline};
use pipeline::DebugPipeline;
use std::{
    env,
    io::Cursor,
    mem::MaybeUninit,
    net::{SocketAddr, ToSocketAddrs},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
    sync::{Arc, Mutex},
};
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    signal::unix::{signal, SignalKind},
};

pub mod bpf;
pub mod ma;
pub mod parse;
pub mod pipeline;

fn state_action_to_raw(state: u16, action: Action, rodata: &rodata) -> u32 {
    let action = match action {
        Action::StartCapture(mid) => rodata.a_start_capture | (mid as u16) & rodata.a_id_mask,
        Action::EndCapture(cid, mid) => {
            let id = (cid as u16) << 6 | (mid as u16);
            rodata.a_end_capture | id & rodata.a_id_mask
        }
        Action::Match(fid) => rodata.a_match | (fid as u16) & rodata.a_id_mask,
        Action::Done => rodata.a_done,
        Action::None => 0,
    };

    ((action as u32) << 16) | (state as u32)
}

fn inject_parser(parser: HttpParser, skel: &mut OpenProxySkel) -> Result<()> {
    for (from, to, input, action) in parser.iter_transitions() {
        let val = state_action_to_raw(*to, *action, skel.maps.rodata_data);
        skel.maps.rodata_data.s2ts[*from as usize][*input as usize] = val;
    }

    Ok(())
}

fn add_socket_to_wait_list<A: ToSocketAddrs, M: MapCore>(
    map: &M,
    addr: &A,
    act: pr_sock_action,
    flags: MapFlags,
) -> Result<()> {
    let addr = addr
        .to_socket_addrs()?
        .next()
        .expect("Failed to resolve address");

    let akey = addr_key {
        ip4: addr.try_into_ne_octets()?,
        port: addr.port() as u32,
    };
    let akey = unsafe { akey.as_bytes() };
    let val = unsafe { act.as_bytes() };

    map.update(akey, &val, flags)?;

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

fn fib_insert_downstream<M: MapCore>(map: &M, key: addr_key, val: &sock_key) -> Result<()> {
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
    pub config: Config,

    skel: ProxySkel<'obj>,
    #[allow(dead_code)]
    sockops: Link,

    binder: Arc<SocketBinder>,

    upstream_pool: Arc<Mutex<Vec<TcpStream>>>,
    new_upstream: Arc<Mutex<Box<dyn NewUpstream>>>,
}

unsafe impl<'obj> Send for Proxy<'obj> {}

unsafe impl<'obj> Sync for Proxy<'obj> {}

impl<'obj> Proxy<'obj> {
    pub fn attach<A: ToSocketAddrs>(
        address: A,
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
        if log_enabled!(log::Level::Debug) {
            open_skel.progs.msg_verdict.set_log_level(1);
        }

        // TODO: configure the parser according to the config
        let mut parser = HttpParser::new(
            open_skel.maps.rodata_data.s_init,
            open_skel.maps.rodata_data.s_any,
        );
        parser.match_http_uri()?;
        parser.match_http_hdr("content-length")?;
        parser.match_http_hdr("backend")?;
        parser.match_http_hdr_auth()?;

        // this is necessary so that the DFA won't
        // parse beyond the HTTP header
        parser.done_on_http_hdr_end()?;

        inject_parser(parser, &mut open_skel)?;

        open_skel.maps.rodata_data.ip4 = address.try_into_ne_octets()?;
        open_skel.maps.rodata_data.port = address.port() as u32;

        let skel = open_skel.load()?;

        let sock_map_fd = skel.maps.sock_map.as_fd().as_raw_fd();

        let cgroup_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open("/sys/fs/cgroup")?
            .into_raw_fd();

        let sockops = skel.progs.monitor_sockets.attach_cgroup(cgroup_fd)?;

        skel.progs.msg_verdict.attach_sockmap(sock_map_fd)?;

        let dests = config
            .hosts
            .iter()
            .flat_map(|h| h.instances.clone())
            .map(|addr| match addr.ip() {
                std::net::IpAddr::V4(ip) => Ok(ip),
                _ => Err(anyhow!("Only IPv4 addresses are supported")),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let binder = SocketBinder::new(12345, dests)?;

        let mut pipeline = DebugPipeline::new(config.clone())?;
        let new_upstream = pipeline.create_new_upstream()?;
        let new_upstream = Mutex::new(new_upstream);

        let crypto = &skel.progs.crypto_setup;
        let input = libbpf_rs::ProgramInput::default();

        let res = crypto.test_run(input)?;
        if res.return_value != 0 {
            let err = std::io::Error::from_raw_os_error(res.return_value as i32);
            error!("Crypto setup failed: {:?}", err);
            bail!("Crypto setup failed");
        }

        debug!("Crypto setup successful");

        Ok(Self {
            address,
            config,
            skel,
            sockops,
            binder: Arc::new(binder),
            upstream_pool: Arc::new(Mutex::new(Vec::new())),
            new_upstream: Arc::new(new_upstream),
        })
    }

    pub async fn listen(self) -> Result<()> {
        let fib = self.get_upstream_fib()?;
        let addrs = self.new_upstream.lock().unwrap().all_upstream_fts();
        for addr in addrs {
            add_pqueue_to_fib(&fib, addr)?;
        }
        add_pqueue_to_fib(&fib, self.new_upstream.lock().unwrap().reverse_proxy_ft())?;

        let sock_wait_list = self.get_sock_wait_list()?;
        add_socket_to_wait_list(
            &sock_wait_list,
            &self.address,
            pr_sock_action::PR_ADD_REMOTE,
            MapFlags::ANY,
        )?;

        info!("Listening on {}", self.address);

        let socket = TcpSocket::new_v4()?;
        socket.set_reuseaddr(true)?;
        socket.bind(self.address)?;
        let listener = socket.listen(4096)?;

        let profile = env::var("BPF_PROFILE").unwrap_or("0".to_string());

        if profile == "1" {
            let this = Arc::new(&self);
            tokio::spawn(unsafe {
                let this = std::mem::transmute::<Arc<&Proxy>, Arc<&'static Proxy>>(this);
                async move {
                    let mut sigterm = signal(SignalKind::terminate()).unwrap();
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {},
                        _ = sigterm.recv() => {},
                    }

                    info!("Profile stats printed to the eBPF tracelog");
                    this.print_profile_stats().await;
                    exit(0)
                }
            });
        }

        loop {
            self.accept(&listener).await?;
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

    async fn accept(&self, listener: &TcpListener) -> Result<()> {
        let (downstream, downstream_addr) = listener.accept().await?;
        debug!("Accepted connection on port {:?}", downstream_addr.port());

        if let Err(e) = self.handle_downstream(downstream) {
            error!("Error handling downstream connection: {:?}", e);
        }

        Ok(())
    }

    fn handle_downstream(&self, downstream: TcpStream) -> Result<()> {
        let addr = self.address.clone();
        let sock_wait_list = self.get_sock_wait_list()?;
        let utrn_wait_list = self.get_utrn_wait_list()?;
        let fib_downstream = self.get_downstream_fib()?;
        let binder = self.binder.clone();
        let upstream_pool = self.upstream_pool.clone();
        let new_upstream = self.new_upstream.clone();

        tokio::spawn(async move {
            let dkey = sock_key::try_from((&downstream.peer_addr().unwrap(), &addr)).unwrap();
            let mut buf = Vec::with_capacity(8192);
            let mut upstreams = Vec::new();

            let res = loop {
                // wait until the downstream connection is readable
                match downstream.readable().await {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(()) => {}
                }

                match downstream.try_read_buf(&mut buf) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(0) => break Ok(()),
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
                    .lookup_and_delete_as(&dkey)
                    .expect("Failed to lookup utrn_wait_list");

                let Some(us_remote_addr) = us_remote_addr else {
                    warn!(
                        "No address found in wait list for downstream connection: [{:?}->{:?}]",
                        &downstream.peer_addr().unwrap(),
                        &us_remote_addr
                    );
                    continue;
                };

                let us_remote_addr: SocketAddr = us_remote_addr.into();
                debug!("Connecting to {}", us_remote_addr);
                let us_sock = binder.bind(us_remote_addr.ip()).unwrap();
                let us_local_addr = us_sock.local_addr().unwrap();

                debug!("Bound to socket: {}", us_local_addr);

                fib_insert_downstream(
                    &fib_downstream,
                    addr_key::try_from(&us_local_addr).unwrap(),
                    &dkey,
                )
                .expect("Failed to insert into FIB");

                if let Err(e) = add_socket_to_wait_list(
                    &sock_wait_list,
                    &us_local_addr,
                    pr_sock_action::PR_ADD_REMOTE,
                    MapFlags::NO_EXIST,
                ) {
                    error!(
                        "Failed to add socket [{:?}->{:?}] to wait list: {:?}",
                        us_local_addr, us_remote_addr, e
                    );
                    break Err(e);
                }

                debug!(
                    "Opening upstream connection [{}->{}] for port {}",
                    us_local_addr,
                    us_remote_addr,
                    downstream.peer_addr().unwrap().port()
                );
                let mut upstream = us_sock.connect(us_remote_addr).await.unwrap();

                let msg = buf.drain(..req_len).collect::<Vec<u8>>();
                let mut req_buf = Cursor::new(&msg);
                upstream.write_all_buf(&mut req_buf).await.unwrap();

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

    fn get_sock_wait_list(&self) -> Result<MapHandle> {
        let id = self.skel.maps.sock_wait_list.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
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
}
