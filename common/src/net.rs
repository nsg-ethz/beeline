use anyhow::{bail, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub fn get_gw_ip(ip: Ipv4Addr) -> Ipv4Addr {
    if ip.is_loopback() {
        ip
    } else {
        let octets = ip.octets();
        Ipv4Addr::new(octets[0], octets[1], octets[2], 1)
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
