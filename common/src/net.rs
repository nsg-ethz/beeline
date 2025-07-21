use anyhow::{bail, Result};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::atomic::AtomicU16,
};
use tokio::net::TcpSocket;

pub fn get_gw_ip(ip: Ipv4Addr) -> Ipv4Addr {
    if ip.is_loopback() {
        ip
    } else {
        let octets = ip.octets();
        Ipv4Addr::new(octets[0], octets[1], octets[2], 1)
    }
}

pub struct SocketBinder {
    ports: HashMap<Ipv4Addr, AtomicU16>,
}

impl SocketBinder {
    pub fn new<I>(start: u16, dests: I) -> Result<Self>
    where
        I: IntoIterator<Item = Ipv4Addr>,
    {
        let mut ports: HashMap<Ipv4Addr, AtomicU16> = dests
            .into_iter()
            .map(|ip| (get_gw_ip(ip), AtomicU16::new(start)))
            .collect();

        ports.insert(Ipv4Addr::LOCALHOST, AtomicU16::new(start));

        Ok(Self { ports })
    }

    pub fn bind(&self, ip: IpAddr) -> Result<TcpSocket> {
        let ip = match ip {
            IpAddr::V4(ip) => ip,
            _ => bail!("IPv6 not supported"),
        };

        let gw = get_gw_ip(ip);
        let port = self.ports.get(&gw).expect("Unknown destination");

        loop {
            let port = port.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if port == u16::MAX {
                bail!("Ports exhausted for destination {}", ip);
            }

            let socket = TcpSocket::new_v4()?;
            let addr = SocketAddrV4::new(gw, port);

            if socket.bind(addr.into()).is_ok() {
                return Ok(socket);
            }
        }
    }
}

pub trait TryIntoRawOctets {
    fn try_into_ne_octets(&self) -> Result<u32>;
}

impl TryIntoRawOctets for SocketAddr {
    fn try_into_ne_octets(&self) -> Result<u32> {
        match self {
            SocketAddr::V4(addr) => Ok(u32::from_ne_bytes(addr.ip().octets())),
            _ => bail!("TryIntoRawOctets only supports IPv4 addresses"),
        }
    }
}

impl TryIntoRawOctets for IpAddr {
    fn try_into_ne_octets(&self) -> Result<u32> {
        match self {
            IpAddr::V4(ip) => Ok(u32::from_ne_bytes(ip.octets())),
            _ => bail!("TryIntoRawOctets only supports IPv4 addresses"),
        }
    }
}

impl TryIntoRawOctets for Ipv4Addr {
    fn try_into_ne_octets(&self) -> Result<u32> {
        Ok(u32::from_ne_bytes(self.octets()))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::{str::FromStr, sync::Arc};

    #[tokio::test]
    async fn it_never_allocates_the_same_port() {
        let ip = Ipv4Addr::from_str("127.0.0.1").unwrap();
        let hosts = vec![ip];
        let binder = Arc::new(SocketBinder::new(12345, hosts.into_iter()).unwrap());

        loop {
            let b1 = binder.clone();
            let t1 = tokio::spawn(async move { b1.bind(IpAddr::V4(ip)) });
            let b2 = binder.clone();
            let t2 = tokio::spawn(async move { b2.bind(IpAddr::V4(ip)) });

            let res = tokio::try_join!(t1, t2).unwrap();
            assert!(res.0.is_ok() && res.1.is_ok());

            let p1 = res.0.unwrap().local_addr().unwrap().port();
            let p2 = res.1.unwrap().local_addr().unwrap().port();
            assert_ne!(p1, p2);

            if p1 > 10000 || p2 > 10000 {
                break;
            }
        }
    }
}
