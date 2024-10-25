use anyhow::{bail, Result};
use as_bytes::AsBytes;
use crate::{
    bpf::{*, types::*},
    config::{Config, Destination},
    parse::{http::HttpParser, Action}
};
use libbpf_rs::{skel::{OpenSkel, SkelBuilder}, Link, MapCore, MapFlags, MapImpl, MapMut};
use log::{debug, info, log_enabled};
use std::{mem::MaybeUninit, net::{IpAddr, SocketAddr, ToSocketAddrs}, os::{fd::{AsFd, AsRawFd, IntoRawFd}, unix::fs::OpenOptionsExt}, sync::Arc};
use tokio::{io::copy, net::{TcpListener, TcpStream}};

mod bpf {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/proxy.skel.rs"
    ));
}
pub mod config;
pub mod parse;

trait TryIntoRawOctets {

    fn try_into_ne_octets(&self) -> Result<u32>;

}

impl TryIntoRawOctets for SocketAddr {

    fn try_into_ne_octets(&self) -> Result<u32> {
        match self.ip() {
            IpAddr::V4(ip) => Ok(u32::from_ne_bytes(ip.octets())),
            _ => bail!("RouteKey only supports IPv4 addresses")
        }
    }

}

impl TryFrom<(&SocketAddr, &SocketAddr)> for sock_key {
    
    type Error = anyhow::Error;

    fn try_from((local, remote): (&SocketAddr, &SocketAddr)) -> Result<Self> {
        let local_ip4 = local.try_into_ne_octets()?;
        let remote_ip4 = remote.try_into_ne_octets()?;
        
        Ok(sock_key {
            local: addr_key {
                ip4: local_ip4,
                port: local.port() as u32,
            },
            remote: addr_key {
                ip4: remote_ip4,
                port: remote.port() as u32,
            }
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
    sock_id: u32,
    skel: Option<ProxySkel<'obj>>,
    sockops: Option<Link>,
    upstreams: Vec<TcpStream>,
}

impl<'obj> Proxy<'obj> {

    pub fn new<A: ToSocketAddrs>(address: A, config: Config) -> Result<Self> {
        let address = address.to_socket_addrs()?
            .next()
            .expect("Failed to resolve address");

        Ok(Self {
            address,
            config,
            sock_id: 0,
            skel: None,
            sockops: None,
            upstreams: Vec::new(),
        })
    }

    pub fn attach(&mut self, open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>) -> Result<()> {
        let skel_builder = ProxySkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if log_enabled!(log::Level::Debug) {
            open_skel.progs.msg_verdict.set_log_level(1);
        }

        let mut parser = HttpParser::new(open_skel.maps.rodata_data.s_init, open_skel.maps.rodata_data.s_any);
        parser.set_http_hdr("backend", "doesntmatter")?;
        parser.set_http_hdr("content-length", "whatever")?;

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

    pub async fn listen(&mut self) -> Result<()> {
        let addr = self.address;
        info!("Listening on {}", addr);

        let listener = TcpListener::bind(&addr).await?;
        loop {
            let sock_id = self.get_new_sock_id();
            self.add_socket_to_wait_list(&addr, sock_id)?;
            self.accept(&listener).await?;
        }
    }

    async fn accept(&mut self, listener: &TcpListener) -> Result<()> {
        if self.skel.is_none() {
            bail!("eBPF program has not been attached");
        }

        let (downstream, downstream_addr) = listener.accept().await?;
        debug!("Accepted connection on port {:?}", downstream_addr.port());

        self.handle_downstream(downstream).await?;

        Ok(())
    }

    async fn handle_downstream(&mut self, mut downstream: TcpStream) -> Result<()> {
        let dkey = sock_key::try_from((&downstream.peer_addr()?, &self.address))?;
        let dkey = unsafe { dkey.as_bytes() };
        let sock_id = self.get_new_sock_id();
        let wait_list = &self.skel.as_ref().unwrap().maps.forward_wait_list;
        let forward_map = &self.skel.as_ref().unwrap().maps.forward_map;

        loop {
            // wait until the downstream connection is readable
            if downstream.readable().await.is_err() {
                continue;
            }

            // if it is, it means that the proxy needs userspace to open a new connection
            let val = wait_list.lookup_and_delete(&dkey)
                .expect("Key not found");

            if let Some(val) = val {
                let (head, body, _tail) = unsafe {
                    val.align_to::<forwarding_decision>()
                };
                if !head.is_empty() || body.len() != 1 {
                    bail!("Invalid value size");
                }

                let fd = body[0];
                debug!("Downstream connection requests new connection: {:?}", fd);

                let upstream_addr = if fd.backend == 1 {
                    "127.0.0.1:8001"
                }
                else {
                    "127.0.0.1:8002"
                };

                self.add_socket_to_wait_list(&upstream_addr, sock_id)?;
                let sock_id = sock_id.to_ne_bytes();
                wait_list.update(dkey, val.as_slice(), MapFlags::ANY)?;
                forward_map.update(val.as_slice(), &sock_id, MapFlags::ANY)?;

                let mut upstream = TcpStream::connect(upstream_addr).await?;
                copy(&mut downstream, &mut upstream).await?;

                self.upstreams.push(upstream);
            }

            break;
        }

        Ok(())
    }

    fn get_new_sock_id(&mut self) -> u32 {
        let id = self.sock_id;
        self.sock_id += 1;
        id
    }

    fn add_socket_to_wait_list<A: ToSocketAddrs>(&self, addr: A, sock_id: u32) -> Result<()> {
        let addr = addr.to_socket_addrs()?
            .next()
            .expect("Failed to resolve address");

        let val = sock_id.to_ne_bytes();
        let wait_list = &self.skel.as_ref().unwrap().maps.sock_wait_list;
        let akey = addr_key {
            ip4: addr.try_into_ne_octets()?,
            port: addr.port() as u32,
        };
        let akey = unsafe { akey.as_bytes() };

        debug!("Adding socket to wait list: {:?}", addr);

        wait_list.update(akey, &val, MapFlags::ANY)?;

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