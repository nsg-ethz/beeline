#![allow(unused_imports)]

use anyhow::{bail, Result};
use as_bytes::AsBytes;
use libbpf_rs::{MapCore, MapFlags};
use crate::net::TryIntoRawOctets;
use std::{mem::size_of, net::SocketAddr};
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

pub trait TypedLookUp {

    fn lookup_as<K: AsBytes, V: Copy>(&self, key: &K, flags: MapFlags) -> Result<Option<V>>;
    fn lookup_and_delete_as<K: AsBytes, V: Copy>(&self, key: &K) -> Result<Option<V>>;

}

impl<M> TypedLookUp for M where M: MapCore {

    fn lookup_as<K: AsBytes, V: Copy>(&self, key: &K, flags: MapFlags) -> Result<Option<V>> {
        if size_of::<V>() as u32 != self.value_size() {
            bail!("Expected value size {} but got {}", self.value_size(), size_of::<V>());
        }

        let key = unsafe { key.as_bytes() };
        let val = self.lookup(key, flags)?;
        let val = val.and_then(|val| align_val_to::<V>(&val));

        Ok(val)
    }

    fn lookup_and_delete_as<K: AsBytes, V: Copy>(&self, key: &K) -> Result<Option<V>> {
        if size_of::<V>() as u32 != self.value_size() {
            bail!("Expected value size {} but got {}", self.value_size(), size_of::<V>());
        }

        let key = unsafe { key.as_bytes() };
        let val = self.lookup_and_delete(key)?;
        let val = val.and_then(|val| align_val_to::<V>(&val));

        Ok(val)
    }

}

fn align_val_to<V: Copy>(val: &[u8]) -> Option<V> {
    let (head, body, _tail) = unsafe {
        val.align_to::<V>()
    };
    if !head.is_empty() || body.len() != 1 {
        return None
    }

    Some(body[0])
}