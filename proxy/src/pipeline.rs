use anyhow::{anyhow, bail, Ok, Result};
use as_bytes::AsBytes;
use crate::{align_val_to, ma::*, bpf::types::*};
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use std::{collections::HashMap, hash::{Hash, Hasher}, net::SocketAddr, str::FromStr};

impl Eq for frwd_token {}

impl PartialEq for frwd_token {

    fn eq(&self, other: &Self) -> bool {
        self.conn_id == other.conn_id && 
        self.direction == other.direction &&    
        self.backend == other.backend && 
        self.num_bytes_min == other.num_bytes_min
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
    maps: HashMap<String, MapHandle>
}

impl Pipeline for DebugPipeline {

    fn new(maps: HashMap<String, MapHandle>) -> Result<Self> {
        Ok(DebugPipeline {
            maps
        })
    }

    fn create_timers(&mut self) -> Result<Vec<Box<dyn Timer>>> {
        Ok(vec![Box::new(UpdateForwardMap::new(&self.maps)?)])
    }

    fn create_uturns(&mut self) -> Result<Vec<Box<dyn Uturn>>> {
        Ok(vec![])
    }

    fn create_new_upstream(&mut self) -> Result<Box<dyn NewUpstream>> {
        Ok(Box::new(ConnectToBackend {}))
    }

}

pub struct UpdateForwardMap {
    upstreams: HashMap<frwd_token, Vec<sock_key>>,
    us_conn_map: MapHandle,
    frwd_map: MapHandle
}

impl UpdateForwardMap {

    pub fn new(maps: &HashMap<String, MapHandle>) -> Result<Self> {
        let us_conn_map = maps.get("us_conn_map")
            .ok_or(anyhow!("us_conn_map not found"))?;

        let frwd_map = maps.get("frwd_map")
            .ok_or(anyhow!("frwd_map not found"))?;

        Ok(UpdateForwardMap {
            upstreams: HashMap::new(),
            us_conn_map: MapHandle::try_from(us_conn_map)?,
            frwd_map: MapHandle::try_from(frwd_map)?
        })
    }

}

impl Timer for UpdateForwardMap {

    fn monitor_upstream(&mut self, key: &sock_key, ft: &frwd_token) {
        self.upstreams.entry(*ft)
            .or_insert(Vec::new())
            .push(key.clone());
    }

    fn monitor_downstream(&mut self, _: &sock_key) {}
    

    fn trigger(&mut self) -> Result<()> {
        let mut states = HashMap::new();

        self.us_conn_map.lookup_batch(50, MapFlags::ANY, MapFlags::ANY)?
            .for_each(|(k, v)| {
                let k = align_val_to::<addr_key>(k.as_slice()).unwrap();
                let v = align_val_to::<us_conn_state>(v.as_slice()).unwrap();
                states.insert(k, v);
            });

        let mut keys = Vec::new();
        let mut vals = Vec::new();
        for (ft, ft_socks) in self.upstreams.iter() {
            let mut min_bytes = u32::max_value();
            let mut min_bytes_key = None;

            for sock in ft_socks.into_iter() {                    
                // the state for this specific key might not exist because no request
                // has been forwarded to this upstream connection yet
                if let Some(val) = states.get(&sock.local) {
                    if val.num_bytes < min_bytes {
                        min_bytes = val.num_bytes;
                        min_bytes_key = Some(sock);
                    }
                }
            }

            if let Some(sock) = min_bytes_key {
                // TODO: add metric flags here
                let ft = frwd_token {
                    num_bytes_min: 1,
                    ..*ft
                };

                keys.push(ft);
                vals.push(sock);
            }
        }

        let len = keys.len() as u32;
        if len > 0 {
            let mut keys_raw = Vec::new();
            for key in keys.iter() {
                let key = unsafe { key.as_bytes() };
                keys_raw.extend_from_slice(key);
            }

            let keys = keys_raw.as_slice();

            let mut vals_raw = Vec::new();
            for val in vals.iter() {
                let val = unsafe { val.as_bytes() };
                vals_raw.extend_from_slice(val);
            }
            let vals = vals_raw.as_slice();

            self.frwd_map.update_batch(keys, vals, len, MapFlags::ANY, MapFlags::ANY)?;
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
    
        let addr = if ft.backend == 1 { "127.0.0.1:8001" }
        else { "127.0.0.1:8002" };
        let addr = SocketAddr::from_str(&addr)?;
    
        Ok(addr)
    }

}
