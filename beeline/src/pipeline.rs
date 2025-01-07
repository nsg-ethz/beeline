use crate::{align_val_to, bpf::types::*, ma::*};
use anyhow::{anyhow, bail, Ok, Result};
use as_bytes::AsBytes;
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    net::SocketAddr,
    str::FromStr,
};

impl Eq for frwd_token {}

impl PartialEq for frwd_token {
    fn eq(&self, other: &Self) -> bool {
        self.conn_id == other.conn_id
            && self.direction == other.direction
            && self.backend == other.backend
            && self.num_bytes_min == other.num_bytes_min
    }
}

impl Hash for frwd_token {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.conn_id.hash(state);
        self.direction.hash(state);
        self.backend.hash(state);
        self.num_bytes_min.hash(state);
    }
}

pub struct DebugPipeline {
    maps: HashMap<String, MapHandle>,
}

impl Pipeline for DebugPipeline {
    fn new(maps: HashMap<String, MapHandle>) -> Result<Self> {
        Ok(DebugPipeline { maps })
    }

    fn create_timers(&mut self) -> Result<Vec<Box<dyn Timer>>> {
        Ok(vec![Box::new(UpdateForwardMap::new(&self.maps)?)])
    }

    fn create_new_upstream(&mut self) -> Result<Box<dyn NewUpstream>> {
        Ok(Box::new(ConnectToBackend {}))
    }
}

pub struct UpdateForwardMap {
    upstreams: HashMap<frwd_token, Vec<sock_key>>,
    us_conn_map: MapHandle,
    fib: MapHandle,
}

impl UpdateForwardMap {
    pub fn new(maps: &HashMap<String, MapHandle>) -> Result<Self> {
        let us_conn_map = maps
            .get("us_conn_map")
            .ok_or(anyhow!("us_conn_map not found"))?;

        let fib = maps.get("fib").ok_or(anyhow!("fib not found"))?;

        Ok(UpdateForwardMap {
            upstreams: HashMap::new(),
            us_conn_map: MapHandle::try_from(us_conn_map)?,
            fib: MapHandle::try_from(fib)?,
        })
    }
}

impl Timer for UpdateForwardMap {
    fn monitor_upstream(&mut self, key: &sock_key, ft: &frwd_token) {
        self.upstreams
            .entry(*ft)
            .or_insert(Vec::new())
            .push(key.clone());
    }

    fn monitor_downstream(&mut self, _: &sock_key) {}

    fn trigger(&mut self) -> Result<()> {
        let mut states = HashMap::new();

        self.us_conn_map
            .lookup_batch(50, MapFlags::ANY, MapFlags::ANY)?
            .for_each(|(k, v)| {
                let k = align_val_to::<addr_key>(k.as_slice()).unwrap();
                let v = align_val_to::<us_conn_state>(v.as_slice()).unwrap();
                states.insert(k, v);
            });

        let mut pqueues = Vec::new();
        self.fib
            .lookup_batch(50, MapFlags::ANY, MapFlags::ANY)?
            .for_each(|(_, v)| {
                let v = align_val_to::<u32>(v.as_slice()).unwrap();
                pqueues.push(v);
            });

        let key: [u8; 0] = [];
        for id in pqueues.iter() {
            let queue = MapHandle::from_map_id(*id)?;
            let mut socks = Vec::new();

            while let Some(val) = queue.lookup_and_delete(&key)? {
                let val = align_val_to::<sock_key>(val.as_slice()).unwrap();
                socks.push(val);
            }

            socks.sort_by(|lhs, rhs| {
                let lhs_state = states.get(&lhs.local).unwrap();
                let rhs_state = states.get(&rhs.local).unwrap();

                lhs_state.num_bytes.cmp(&rhs_state.num_bytes)
            });

            for sock in socks.iter() {
                let value = unsafe { sock.as_bytes() };
                queue.update(&key, &value, MapFlags::ANY)?;
            }
        }

        Ok(())
    }
}

pub struct ConnectToBackend {}

impl NewUpstream for ConnectToBackend {
    fn new_upstream_connection(&mut self, ctx: &pipeline_ctx) -> Result<SocketAddr> {
        let ft = ctx.ft;
        if ft.direction != 2 {
            bail!("Invalid direction: {}", ft.direction);
        }

        let addr = if ft.backend == 1 {
            "127.0.0.1:8001"
        } else {
            "127.0.0.1:8002"
        };
        let addr = SocketAddr::from_str(&addr)?;

        Ok(addr)
    }
}
