#![allow(unused_imports)]

use anyhow::{bail, Result};
use as_bytes::AsBytes;
use common::net::TryIntoRawOctets;
use libbpf_rs::{MapCore, MapFlags};
use std::{
    hash::{Hash, Hasher},
    mem::size_of,
    net::SocketAddr,
};
use types::*;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bpf/proxy.skel.rs"
));

impl Eq for addr_key {}

impl PartialEq for addr_key {
    fn eq(&self, other: &Self) -> bool {
        self.ip4 == other.ip4 && self.port == other.port
    }
}

impl Hash for addr_key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip4.hash(state);
        self.port.hash(state);
    }
}

impl TryFrom<&SocketAddr> for addr_key {
    type Error = anyhow::Error;

    fn try_from(addr: &SocketAddr) -> Result<Self> {
        Ok(addr_key {
            ip4: addr.try_into_ne_octets()?,
            port: addr.port() as u32,
        })
    }
}

impl TryFrom<(&SocketAddr, &SocketAddr)> for sock_key {
    type Error = anyhow::Error;

    fn try_from((local, remote): (&SocketAddr, &SocketAddr)) -> Result<Self> {
        Ok(sock_key {
            local: addr_key::try_from(local)?,
            remote: addr_key::try_from(remote)?,
        })
    }
}
