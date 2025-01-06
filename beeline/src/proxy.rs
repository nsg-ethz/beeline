use crate::{
    bpf::{types::*, TypedLookUp, *},
    net::{SocketBinder, TryIntoRawOctets},
    parse::{http::HttpParser, Action},
};
use anyhow::{anyhow, bail, Result};
use as_bytes::AsBytes;
use common::Config;
use libbpf_rs::{
    set_print,
    skel::{OpenSkel, SkelBuilder},
    Link, MapCore, MapFlags, MapHandle, MapType, PrintLevel,
};
use log::{debug, error, info, log_enabled, warn};
use ma::{NewUpstream, Pipeline, Timer};
use pipeline::DebugPipeline;
use std::{
    collections::HashMap,
    io::Cursor,
    mem::MaybeUninit,
    net::{SocketAddr, ToSocketAddrs},
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{self, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task, time,
};

pub mod bpf;
pub mod ma;
pub mod net;
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
    ft: Option<frwd_token>,
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

    let val = opt_frwd_token {
        is_some: ft.is_some() as u8,
        inner: ft.unwrap_or_default(),
    };
    let val = unsafe { val.as_bytes() };

    map.update(akey, &val, flags)?;

    Ok(())
}

fn add_pqueue_to_fib<M: MapCore>(map: &M, ft: frwd_token) -> Result<()> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        map_flags: libbpf_sys::BPF_ANY,
        // bpf_map_create_opts might have padding fields on some platform
        ..Default::default()
    };

    let pqueue = MapHandle::create(
        MapType::Queue,
        Some("fib_pqueue"),
        0,
        size_of::<sock_key>() as u32,
        2048,
        &opts,
    )?;

    let key = unsafe { ft.as_bytes() };

    let val = pqueue.as_fd();
    let val = unsafe { val.as_bytes() };

    match map.update(key, &val, MapFlags::NO_EXIST) {
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

fn add_forward_rule_to_wait_list<A: ToSocketAddrs, M: MapCore>(
    map: &M,
    local_addr: &A,
    remote_addr: &A,
    ctx: &pipeline_ctx,
) -> Result<()> {
    let local_addr = local_addr
        .to_socket_addrs()?
        .next()
        .expect("Failed to resolve local address");

    let remote_addr = remote_addr
        .to_socket_addrs()?
        .next()
        .expect("Failed to resolve local address");

    let skey = sock_key::try_from((&local_addr, &remote_addr))?;
    let skey = unsafe { skey.as_bytes() };
    let ctx = unsafe { ctx.as_bytes() };

    map.update(skey, ctx, MapFlags::ANY)?;

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
    upstreams: Arc<Mutex<Vec<TcpStream>>>,

    timers: Arc<Vec<Mutex<Box<dyn Timer>>>>,
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
            .expect("Failed to resolve address");

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
        parser.match_http_hdr("backend")?;
        parser.match_http_hdr("content-length")?;
        parser.match_http_hdr("conn-id")?;
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

        let maps = HashMap::from([
            ("us_conn_map", skel.maps.us_conns.info()?.info.id),
            ("fib", skel.maps.fib.info()?.info.id),
        ]);
        let maps = maps
            .iter()
            .map(|(k, v)| (k.to_string(), MapHandle::from_map_id(*v).unwrap()))
            .collect::<HashMap<_, _>>();

        let mut pipeline = DebugPipeline::new(maps)?;
        let timers = pipeline
            .create_timers()?
            .into_iter()
            .map(|t| Mutex::new(t))
            .collect();

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
            upstreams: Arc::new(Mutex::new(Vec::new())),
            timers: Arc::new(timers),
            new_upstream: Arc::new(new_upstream),
        })
    }

    pub async fn listen(self) -> Result<()> {
        let addr = self.address;
        info!("Listening on {}", addr);

        self.trigger_timers()?;

        let listener = TcpListener::bind(&addr).await?;
        loop {
            self.accept(&listener).await?;
        }
    }

    async fn accept(&self, listener: &TcpListener) -> Result<()> {
        let sock_wait_list = self.get_sock_wait_list()?;
        add_socket_to_wait_list(&sock_wait_list, &self.address, None, MapFlags::ANY)?;

        let (downstream, downstream_addr) = listener.accept().await?;
        debug!("Accepted connection on port {:?}", downstream_addr.port());

        if let Err(e) = self.handle_downstream(downstream).await {
            error!("Error handling downstream connection: {:?}", e);
        }

        Ok(())
    }

    async fn handle_downstream(&self, downstream: TcpStream) -> Result<()> {
        let addr = self.address.clone();
        let sock_wait_list = self.get_sock_wait_list()?;
        let utrn_wait_list = self.get_utrn_wait_list()?;
        let fib = self.get_fib()?;
        let binder = self.binder.clone();
        let upstreams = self.upstreams.clone();
        let timers = self.timers.clone();
        let new_upstream = self.new_upstream.clone();

        tokio::spawn(async move {
            let dkey = sock_key::try_from((&downstream.peer_addr().unwrap(), &addr)).unwrap();
            let mut buf = Vec::with_capacity(8192);

            let res = 'read_downstream: loop {
                // wait until the downstream connection is readable
                match downstream.readable().await {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(()) => {}
                }

                let buf_len = match downstream.try_read_buf(&mut buf) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(0) => break Ok(()),
                    Ok(len) => len,
                };

                let mut headers = [httparse::EMPTY_HEADER; 64];
                let mut req = httparse::Request::new(&mut headers);
                let hdr_len = req.parse(&buf);
                if let Err(e) = hdr_len {
                    break Err(anyhow!(e));
                }

                let con_len = req
                    .headers
                    .iter()
                    .find(|h| h.name.eq_ignore_ascii_case("content-length"))
                    .and_then(|h| std::str::from_utf8(h.value).ok())
                    .and_then(|v| v.parse::<usize>().ok())
                    .unwrap_or(0);

                let hdr_len = match hdr_len.unwrap() {
                    httparse::Status::Complete(len) => len,
                    httparse::Status::Partial => continue,
                };

                let req_len = hdr_len + con_len;
                if buf_len < req_len {
                    debug!("Request not fully read: {buf_len}/{req_len}");
                    continue;
                }

                // check if there is a pipeline context in the waiting list
                let ctx: Option<pipeline_ctx> = utrn_wait_list
                    .lookup_and_delete_as(&dkey)
                    .expect("Failed to lookup utrn_wait_list");

                if ctx.is_none() {
                    warn!(
                        "No context found in wait list for downstream connection: {:?}",
                        dkey
                    );
                    continue;
                }
                let ctx = ctx.unwrap();

                // check if there is a forwarding token in the waiting list
                let ft = ctx.ft;
                let us_remote_addr = new_upstream
                    .lock()
                    .unwrap()
                    .new_upstream_connection(&ctx)
                    .unwrap();
                let us_sock = binder.bind(us_remote_addr.ip()).unwrap();
                let us_local_addr = us_sock.local_addr().unwrap();

                debug!("Bound to socket: {}", us_local_addr);

                add_forward_rule_to_wait_list(
                    &utrn_wait_list,
                    &us_local_addr,
                    &us_remote_addr,
                    &ctx,
                )
                .unwrap();
                if let Err(e) = add_socket_to_wait_list(
                    &sock_wait_list,
                    &us_local_addr,
                    Some(ft),
                    MapFlags::NO_EXIST,
                ) {
                    error!(
                        "Failed to add socket [{:?}->{:?}] to wait list: {:?}",
                        us_local_addr, us_remote_addr, e
                    );
                    break Err(e);
                }

                add_pqueue_to_fib(&fib, ft).unwrap();
                add_socket_to_wait_list(&sock_wait_list, &us_remote_addr, None, MapFlags::ANY)
                    .unwrap();

                debug!(
                    "Opening upstream connection [{}->{}]",
                    us_local_addr, us_remote_addr
                );
                let mut upstream = us_sock.connect(us_remote_addr).await.unwrap();

                let msg = buf.drain(..req_len).collect::<Vec<u8>>();
                let mut req_buf = Cursor::new(&msg);
                upstream.write_all_buf(&mut req_buf).await.unwrap();

                // upstream connections are automatically reused by the eBPF program
                // adding them to this shared vector allows us to keep them alive
                upstreams.lock().unwrap().push(upstream);

                timers.iter().for_each(|t| {
                    let mut t = t.lock().unwrap();
                    t.monitor_upstream(&dkey, &ft);
                });

                buf.clear();
            };

            if let Err(e) = res {
                error!("Error handling downstream connection: {:?}", e);
            }
        });

        Ok(())
    }

    fn trigger_timers(&self) -> Result<()> {
        // TODO: timers can have their own frequency
        // let timers = self.timers.clone();
        // let update_freq = Duration::from_micros(500);

        // task::spawn(async move {
        //     let mut interval = time::interval(update_freq);

        //     loop {
        //         interval.tick().await;

        //         let res = timers[0].lock().unwrap().trigger();

        //         // TODO: report error with name of timer
        //         if let Err(e) = res {
        //             error!("An error occured in timer {}: {:?}", "UpdateForwardMap", e);
        //         }
        //     }
        // });

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

    fn get_fib(&self) -> Result<MapHandle> {
        let id = self.skel.maps.fib.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
    }
}
