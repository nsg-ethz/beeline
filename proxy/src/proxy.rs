use anyhow::{anyhow, bail, Result};
use as_bytes::AsBytes;
use crate::{
    bpf::{*, types::*},
    config::Config,
    parse::{http::HttpParser, Action}
};
use libbpf_rs::{skel::{OpenSkel, SkelBuilder}, Link, MapCore, MapFlags, MapHandle};
use log::{debug, error, info, log_enabled};
use std::{mem::MaybeUninit, net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs}, os::{fd::{AsFd, AsRawFd, IntoRawFd}, unix::fs::OpenOptionsExt}, str::FromStr, sync::{Arc, Mutex}};
use tokio::{io::{self, AsyncWriteExt}, net::{TcpListener, TcpSocket, TcpStream}};

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

fn add_socket_to_wait_list<A: ToSocketAddrs, M: MapCore>(map: &M, addr: &A, fd: Option<forwarding_decision>) -> Result<()> {
    let addr = addr.to_socket_addrs()?
        .next()
        .expect("Failed to resolve address");

    let akey = addr_key {
        ip4: addr.try_into_ne_octets()?,
        port: addr.port() as u32,
    };
    let akey = unsafe { akey.as_bytes() };

    let val = opt_forwarding_decision {
        is_some: fd.is_some() as u8,
        inner: fd.unwrap_or_default()
    };
    let val = unsafe { val.as_bytes() };

    map.update(akey, &val, MapFlags::ANY)?;

    Ok(())
}

fn add_forward_rule_to_wait_list<A: ToSocketAddrs, M: MapCore>(map: &M, local_addr: &A, remote_addr: &A, fd: forwarding_decision) -> Result<()> {
    let local_addr = local_addr.to_socket_addrs()?
        .next()
        .expect("Failed to resolve local address");

    let remote_addr = remote_addr.to_socket_addrs()?
        .next()
        .expect("Failed to resolve local address");

    let skey = sock_key::try_from((&local_addr, &remote_addr))?;
    let skey = unsafe { skey.as_bytes() };
    let fd = unsafe { fd.as_bytes() };

    map.update(skey, fd, MapFlags::ANY)?;

    Ok(())
}

fn get_configured_dest_addr(config: &Config, fd: &forwarding_decision) -> Result<SocketAddr> {
    if fd.direction != 2 {
        bail!("Invalid direction");
    }

    let dest = config.spec.routes.iter()
        .find(|route| {
            if let Some(backend) = route.predicates.get("backend").and_then(|b| b.parse::<u8>().ok()) {
                if backend != fd.backend {
                    return false;
                }
            }

            true
        })
        .map(|r| &r.destination)
        .expect("No matching route found");

    let host = config.hosts.iter()
        .find(|h| h.name == dest.host)
        .expect(format!("Host not found: {}", dest.host).as_str());

    let addr = format!("{}:{}", host.address, dest.port);
    let addr = SocketAddr::from_str(&addr)?;

    Ok(addr)
}

fn get_new_bound_socket(dest: &SocketAddr, port_range: std::ops::Range<u16>) -> Result<TcpSocket> {
    let ip = if dest.ip().is_loopback() {
        dest.ip()
    }
    else {
        let octets = match dest.ip() {
            IpAddr::V4(ip) => ip.octets(),
            _ => bail!("IPv6 is not supported")
        };
        IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], 254))
    };

    let socket = TcpSocket::new_v4()?;
    for port in port_range {
        let addr = SocketAddr::new(ip, port);

        if let Ok(()) = socket.bind(addr.into()) {
            return Ok(socket);
        }
    }

    bail!("Failed to bind socket")
}

pub struct Proxy<'obj> {
    pub address: SocketAddr,
    pub config: Config,
    skel: ProxySkel<'obj>,

    #[allow(dead_code)]
    sockops: Link,
    upstreams: Arc<Mutex<Vec<TcpStream>>>
}

impl<'obj> Proxy<'obj> {

    pub fn attach<A: ToSocketAddrs>(address: A, config: Config, open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>) -> Result<Self> {
        let address = address.to_socket_addrs()?
            .next()
            .expect("Failed to resolve address");

        let skel_builder = ProxySkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if log_enabled!(log::Level::Debug) {
            open_skel.progs.msg_verdict.set_log_level(1);
        }

        let mut parser = HttpParser::new(open_skel.maps.rodata_data.s_init, open_skel.maps.rodata_data.s_any);
        parser.set_http_hdr("backend", "doesntmatter")?;
        parser.set_http_hdr("content-length", "whatever")?;
        parser.set_http_hdr("conn-id", "lol")?;

        // this is necessary so that the DFA won't
        // parse beyond the HTTP header
        parser.done_on_http_hdr_end()?;

        inject_parser(parser, &mut open_skel)?;

        if let IpAddr::V4(ip) = address.ip() {
            open_skel.maps.rodata_data.ip4 = u32::from_ne_bytes(ip.octets());
        }
        else {
            bail!("IPv6 is not supported");
        }
        open_skel.maps.rodata_data.port = address.port() as u32;

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

        Ok(Self {
            address,
            config,
            skel: skel,
            sockops: sockops,
            upstreams: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub async fn listen(self) -> Result<()> {
        let addr = self.address;
        info!("Listening on {}", addr);

        let mut port_range = 12345..13345;
        let listener = TcpListener::bind(&addr).await?;
        loop {
            self.accept(&listener, port_range.clone()).await?;
            port_range = port_range.end..(port_range.end + 1000);
        }
    }

    async fn accept(&self, listener: &TcpListener, port_range: std::ops::Range<u16>) -> Result<()> {
        let sock_wait_list = self.get_sock_wait_list()?;
        add_socket_to_wait_list(&sock_wait_list, &self.address, None)?;

        let (downstream, downstream_addr) = listener.accept().await?;
        debug!("Accepted connection on port {:?}", downstream_addr.port());

        if let Err(e) = self.handle_downstream(downstream, port_range).await {
            error!("Error handling downstream connection: {:?}", e);
        }

        Ok(())
    }

    async fn handle_downstream(&self, downstream: TcpStream, port_range: std::ops::Range<u16>) -> Result<()> {
        let addr = self.address.clone();
        let forward_wait_list = self.get_forward_wait_list()?;
        let sock_wait_list = self.get_sock_wait_list()?;
        let config = self.config.clone();
        let upstreams = self.upstreams.clone();

        tokio::spawn(async move {
            let dkey = sock_key::try_from((&downstream.peer_addr().unwrap(), &addr))
                .unwrap();
            let dkey = unsafe { dkey.as_bytes() };
            let mut buf = [0u8; 8192];
            let mut new_upstreams = Vec::new();

            let res = loop {
                // wait until the downstream connection is readable
                match downstream.readable().await {
                    Err(ref e)if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(()) => {}
                }

                match downstream.try_read(&mut buf) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(anyhow!(e)),
                    Ok(0) => break Ok(()),
                    Ok(len) => {
                        // if it is, it means that the proxy needs userspace to open a new connection
                        let val = forward_wait_list.lookup_and_delete(&dkey)
                            .expect("No forwarding decision in wait list");

                        if let Some(val) = val {
                            let (head, body, _tail) = unsafe {
                                val.align_to::<forwarding_decision>()
                            };
                            if !head.is_empty() || body.len() != 1 {
                                break Err(anyhow!("Invalid value size"));
                            }

                            let fd = body[0];

                            let us_remote_addr = get_configured_dest_addr(&config, &fd).unwrap();
                            let us_sock = get_new_bound_socket(&us_remote_addr, port_range.clone()).unwrap();
                            let us_local_addr = us_sock.local_addr().unwrap();

                            add_forward_rule_to_wait_list(&forward_wait_list, &us_local_addr, &us_remote_addr, fd).unwrap();
                            add_socket_to_wait_list(&sock_wait_list, &us_local_addr, Some(fd)).unwrap();
                            add_socket_to_wait_list(&sock_wait_list, &us_remote_addr, None).unwrap();

                            // TODO: This should also handle the case where the req doesn't fit into one buffer
                            debug!("Opening upstream connection [{}->{}]", us_local_addr, us_remote_addr);
                            let mut upstream = us_sock.connect(us_remote_addr).await.unwrap();
                            upstream.write(&buf[..len]).await.unwrap();

                            new_upstreams.push(upstream);
                        }
                    }
                }
            };

            if let Err(e) = res {
                error!("Error handling downstream connection: {:?}", e);
            }

            // upstream connections are automatically reused by the eBPF program
            // we just have to keep them alive here
            upstreams.lock()
                .unwrap()
                .extend(new_upstreams.into_iter());
        });

        Ok(())
    }

    fn get_sock_wait_list(&self) -> Result<MapHandle> {
        let id = self.skel.maps.sock_wait_list.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
    }

    fn get_forward_wait_list(&self) -> Result<MapHandle> {
        let id = self.skel.maps.forward_wait_list.info()?.info.id;
        Ok(MapHandle::from_map_id(id)?)
    }

}