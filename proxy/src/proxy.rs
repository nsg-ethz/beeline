use anyhow::{bail, Result};
use as_bytes::AsBytes;
use crate::{
    bpf::{*, types::*},
    config::{Config, Destination},
    parse::{http::HttpParser, Action}
};
use libbpf_rs::{skel::{OpenSkel, SkelBuilder}, Link, MapCore, MapFlags};
use log::{debug, info, log_enabled};
use socket2::Socket;
use std::{collections::HashMap, mem::MaybeUninit, net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs}, os::{fd::{AsFd, AsRawFd, IntoRawFd}, unix::fs::OpenOptionsExt}, vec};

mod bpf {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/proxy.skel.rs"
    ));
}

pub mod config;
pub mod parse;

impl TryFrom<&SocketAddr> for wait_list_key {

    type Error = anyhow::Error;

    fn try_from(addr: &SocketAddr) -> Result<wait_list_key> {

        let ip4 = match addr.ip() {
            IpAddr::V4(ip) => u32::from_ne_bytes(ip.octets()),
            _ => bail!("RouteKey only supports IPv4 addresses")
        };

        Ok(wait_list_key {
            ip4,
            port: addr.port() as u32,
        })
    }

}

impl wait_list_val {

    fn new(sock_key: u32, route_fids: Vec<u32>, route_sock_keys: Vec<u32>) -> Result<wait_list_val> {
        if route_sock_keys.len() != route_fids.len() {
            bail!("Route addresses, sock keys, and FIDs must have the same length");
        }
        if route_fids.len() > 16 {
            bail!("Too many routes");
        }

        let mut fids = [0; 16];
        let mut sock_keys = [0; 16];

        for i in 0..route_fids.len() {
            fids[i] = route_fids[i];
            sock_keys[i] = route_sock_keys[i];
        }

        Ok(wait_list_val {
            sock_key,
            num_routes: route_fids.len() as u32,
            route_fid: fids,
            route_sock_key: sock_keys
        })
    }

}

fn state_action_to_raw(state: u16, action: Action, rodata: &rodata) -> u32 {
    let action = match action {
        Action::StartCapture(mid) => {
            rodata.a_start_capture | (mid as u16) & rodata.a_id_mask
        },
        Action::EndCapture(cid, mid) => {
            let id = (cid as u16) << 6 | (mid as u16);
            rodata.a_end_capture | id & rodata.a_id_mask
        }
        Action::Match(fid) => {
            rodata.a_match | (fid as u16) & rodata.a_id_mask
        },
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

    for (mid, mo) in parser.modifications.iter() {
        let idx = *mid as usize;
        skel.maps.rodata_data.mods[idx].len = mo.replacement.len() as u8;
        skel.maps.rodata_data.mods[idx].tail = mo.tail;
        for (i, c) in mo.replacement.chars().enumerate() {
            skel.maps.rodata_data.mods[idx].str[i] = c as i8;
        }
    }

    Ok(())
}

pub struct Proxy<'obj> {
    pub address: SocketAddr,
    pub config: Config,
    skel: Option<ProxySkel<'obj>>,
    sockops: Option<Link>,
    upstreams: Vec<TcpStream>,
    downstreams: Vec<TcpStream>,
    sock_key: u32
}

impl<'obj> Proxy<'obj> {

    pub fn new<A: ToSocketAddrs>(address: A, config: Config) -> Result<Self> {
        let address = address.to_socket_addrs()?
            .next()
            .expect("Failed to resolve address");

        Ok(Self {
            address,
            config,
            skel: None,
            sockops: None,
            upstreams: Vec::new(),
            downstreams: Vec::new(),
            sock_key: 0
        })
    }

    pub fn attach(&mut self, open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>) -> Result<()> {
        let skel_builder = ProxySkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if log_enabled!(log::Level::Debug) {
            open_skel.progs.msg_verdict.set_log_level(1);
        }

        let mut parser = HttpParser::new(open_skel.maps.rodata_data.s_init, open_skel.maps.rodata_data.s_any);
        // let mut mods = HashMap::new();

        // parser.match_http_hdr("backend", "server1")?;
        // parser.match_http_hdr("backend", "server2")?;
        parser.set_http_hdr("backend", "doesntmatter")?;
        parser.set_http_hdr("content-length", "whatever")?;

        // filters from the config are split into two parts:
        // request and response filters
        // let mut num_filters = 0;
        // for filter in &self.config.spec.http {
        //     // first the req filter is added
        //     // it is added anyways, because it dictates where to route traffic to
        //     let fid = num_filters + 1;
        //     parser.start_new_filter(fid as u8);
        //     num_filters += 1;

        //     for (key, val) in &filter.patterns {
        //         parser.match_http_hdr(&key, &val)?;
        //     }
        
        //     let req = filter.mods
        //         .clone()
        //         .and_then(|h| h.request);

        //     let mids = req.and_then(|req| {
        //         let remove = req.remove.unwrap_or_default()
        //             .iter()
        //             .map(|key| {
        //                 // only add a modification once to the dfa
        //                 if let Some(mid) = mods.get(key) {
        //                     *mid
        //                 }
        //                 else {
        //                     let mid = parser.remove_http_hdr(&key)
        //                         .expect("Failed to add header modification");
        //                     mods.insert(key.clone(), mid.clone());
        //                     mid
        //                 }
        //             })
        //             .collect::<Vec<_>>();

                
        //         Some(remove)
        //     })
        //     .unwrap_or_default();

        //     debug!("req filter {}: {} patterns, {} modifications", fid, filter.patterns.len(), mids.len());

        //     open_skel.maps.rodata_data.filters[fid].num_patterns = filter.patterns.len() as u8;
        //     open_skel.maps.rodata_data.filters[fid].num_modifications = mids.len() as u8;
        //     for (i, mid) in mids.into_iter().enumerate() {
        //         open_skel.maps.rodata_data.filters[fid].mids[i] = mid;
        //     }

        //     // next we add the response filter
        //     // it is only added if the response needs to be modified
        //     let res = filter.mods
        //         .clone()
        //         .and_then(|h| h.response);

        //     if let Some(res) = res {
        //         let fid = num_filters + 1;
        //         parser.start_new_filter(fid as u8);
        //         num_filters += 1;

        //         let remove = res.remove.unwrap_or_default()
        //             .iter()
        //             .map(|key| {
        //                 // only add a modification once to the dfa
        //                 if let Some(mid) = mods.get(key) {
        //                     *mid
        //                 }
        //                 else {
        //                     let mid = parser.remove_http_hdr(&key)
        //                         .expect("Failed to add header modification");
        //                     mods.insert(key.clone(), mid.clone());
        //                     mid
        //                 }
        //             })
        //             .collect::<Vec<_>>();

        //         let mids = remove;
    
        //         debug!("res filter {}: {} modifications", fid, mids.len());
    
        //         open_skel.maps.rodata_data.filters[fid].num_patterns = 0;
        //         open_skel.maps.rodata_data.filters[fid].num_modifications = mids.len() as u8;
        //         for (i, mid) in mids.into_iter().enumerate() {
        //             open_skel.maps.rodata_data.filters[fid].mids[i] = mid;
        //         }
        //     }
        // }

        // this is necessary so that the DFA won't
        // parse beyond the HTTP header
        parser.done_on_http_hdr_end()?;

        inject_parser(parser, &mut open_skel)?;

        if let IpAddr::V4(ip) = self.address.ip() {
            open_skel.maps.rodata_data.ip4 = u32::from_ne_bytes(ip.octets());
        }
        else {
            bail!("IPv6 is not supported");
        }

        open_skel.maps.rodata_data.port = self.address.port() as u32;

        let skel = open_skel.load()?;

        let sock_map_fd = skel.maps
            .sock_map
            .as_fd()
            .as_raw_fd();

        let cgroup_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open("/sys/fs/cgroup")?
            .into_raw_fd();

        let sockops = skel.progs
            .monitor_sockets
            .attach_cgroup(cgroup_fd)?;

        skel.progs
            .msg_verdict
            .attach_sockmap(sock_map_fd)?;

        self.sockops = Some(sockops);
        self.skel = Some(skel);

        Ok(())
    }

    pub fn listen(&mut self) -> Result<()> {
        info!("Listening on {}", self.address);

        let listener = TcpListener::bind(&self.address)?;
        loop {
            self.accept(&listener)?;
        }
    }

    fn get_new_sock_id(&mut self) -> u32 {
        let id = self.sock_key;
        self.sock_key += 1;
        id
    }

    fn accept(&mut self, listener: &TcpListener) -> Result<()> {
        if self.skel.is_none() {
            bail!("eBPF program has not been attached");
        }

        let downstream_sock_key = self.get_new_sock_id();

        // we first bind the sockets to local ports
        // this makes it possible to know the ports before establishing the connection
        let mut port = 12345;
        let mut fid = 1;
        let upstream_sockets = self.config.spec.http
            .clone()
            .iter()
            .map(|filter| {
                let socket = Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
                let dest = &filter.route.first().unwrap().destination;
                let peer_addr = self.get_socket_addr_for_dest(&dest);

                loop {
                    let addr = SocketAddr::new(self.address.ip(), port);

                    if let Err(_) = socket.bind(&addr.into()) {
                        port += 1;
                    }
                    else {
                        debug!("Bind socket to {} for connection to {:?}", port, peer_addr);
                        break;
                    }
                }

                let sock_key = self.get_new_sock_id();
                let req_fid = fid;
                let res_fid = filter.mods
                    .clone()
                    .and_then(|h| h.response)
                    .map(|_| fid + 1);

                fid = res_fid.unwrap_or(req_fid) + 1;
                
                (socket, peer_addr, sock_key, req_fid, res_fid)
            })
            .collect::<Vec<_>>();

        // we now know all but the downstream peer address
        let sock_wait_list = &self.skel.as_ref().unwrap()
            .maps
            .sock_wait_list;

        // add the upstream sockets to the wait list
        // this lets the sockops program know which connections to add to the sockmap
        // the sockops will then populate the route map
        // sockops has to do this, because in userspace we lack the local address 
        // of the downstream socket until it's too late
        for (socket, _, sock_key, _, res_fid) in upstream_sockets.iter() {
            let local_addr = socket.local_addr()?.as_socket_ipv4().unwrap().into();
            let key = wait_list_key::try_from(&local_addr)?;
            let key = unsafe { key.as_bytes() };

            let val = wait_list_val::new(
                *sock_key, 
                vec![res_fid.unwrap_or_default()],
                vec![downstream_sock_key]
            )?;
            let val = unsafe { val.as_bytes() };

            sock_wait_list.update(&key, &val, MapFlags::ANY)?;
        }

        // add the downstream socket to the wait list
        let key = wait_list_key::try_from(&self.address)?;
        let key = unsafe { key.as_bytes() };

        let req_fids = upstream_sockets.iter()
            .map(|(_, _, _, req_fid, _)| *req_fid as u32)
            .collect::<Vec<_>>();
        let sock_keys = upstream_sockets.iter()
            .map(|(_, _, sock_key, _, _)| *sock_key)
            .collect::<Vec<_>>();
        
        let val = wait_list_val::new(
            downstream_sock_key, 
            req_fids,
            sock_keys
        )?;
        let val = unsafe { val.as_bytes() };

        sock_wait_list.update(&key, &val, MapFlags::ANY)?;

        // we first connect upstream to avoid the race condition
        // where the downstream wants to route to upstream, but upstream hasn't connected yet
        for (socket, peer_addr, _, _, _) in upstream_sockets.into_iter() {
            let peer_addr = socket2::SockAddr::from(peer_addr);
            socket.connect(&peer_addr)?;
            let upstream = TcpStream::from(socket);

            self.upstreams.push(upstream);
        }

        // this will block until a connection is established
        let (downstream, downstream_addr) = listener.accept()?;
        debug!("Accepted connection on port {:?}", downstream_addr.port());

        self.downstreams.push(downstream);

        Ok(())
    }

    fn get_socket_addr_for_dest(&self, dest: &Destination) -> SocketAddr {
        let host = self.config.hosts.iter()
            .find(|h| h.name == dest.host)
            .expect(format!("Host not found: {}", dest.host).as_str());

        let addr = format!("{}:{}", host.address, dest.port);
        addr.parse()
            .expect(format!("Invalid address: {}", addr).as_str())
    }

}