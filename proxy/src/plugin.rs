use as_bytes::AsBytes;
use hmac::digest::Update;
use libbpf_rs::{MapCore, MapFlags, MapHandle};
use crate::{align_val_to, ma::Timer, bpf::types::*};
use std::{collections::HashMap, hash::{Hash, Hasher}};

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

pub struct UpdateForwardMap {
    upstreams: HashMap<frwd_token, Vec<sock_key>>
}

impl UpdateForwardMap {

    pub fn new() -> Self {
        UpdateForwardMap {
            upstreams: HashMap::new()
        }
    }

}

impl Timer for UpdateForwardMap {

    fn monitor_upstream(&mut self, key: &sock_key, ft: &frwd_token) {
        self.upstreams.entry(*ft)
            .or_insert(Vec::new())
            .push(key.clone());
    }

    fn monitor_downstream(&mut self, key: &sock_key) {}
    

    fn trigger(&mut self, reads: &HashMap<String, MapHandle>, writes: &HashMap<String, MapHandle>) {
        let mut states = HashMap::new();
        let us_conn_map = reads.get("us_conn_map").unwrap();
        let frwd_map = writes.get("frwd_map").unwrap();

        us_conn_map.lookup_batch(50, MapFlags::ANY, MapFlags::ANY)
            .expect("Failed to lookup us_conn_map")
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

            frwd_map.update_batch(keys, vals, len, MapFlags::ANY, MapFlags::ANY)
                .expect("Failed to update forward map");
        }
    }
}