use anyhow::Result;
use crate::net::TryIntoRawOctets;
use std::net::SocketAddr;
use types::*;

include!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/bpf/proxy.skel.rs"
));

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