use crate::{align_val_to, bpf::types::*, ma::*};
use anyhow::{anyhow, bail, Ok, Result};
use as_bytes::AsBytes;
use common::Config;
use libbpf_rs::{MapCore, MapFlags, MapHandle, MapType};
use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    net::SocketAddr,
    os::fd::{AsFd, AsRawFd},
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
    config: Config,
    maps: HashMap<String, MapHandle>,
}

impl Pipeline for DebugPipeline {
    fn new(config: Config, maps: HashMap<String, MapHandle>) -> Result<Self> {
        Ok(DebugPipeline { config, maps })
    }

    fn create_timers(&mut self) -> Result<Vec<Box<dyn Timer>>> {
        Ok(vec![Box::new(UpdateForwardMap::new(&self.maps)?)])
    }

    fn create_new_upstream(&mut self) -> Result<Box<dyn NewUpstream>> {
        Ok(Box::new(ConnectToBackend {
            config: self.config.clone(),
        }))
    }
}

pub struct UpdateForwardMap {
    fib: MapHandle,
    us_conn_map: MapHandle,
}

impl UpdateForwardMap {
    pub fn new(maps: &HashMap<String, MapHandle>) -> Result<Self> {
        let us_conn_map = maps
            .get("us_conn_map")
            .ok_or(anyhow!("us_conn_map not found"))?;

        let fib = maps.get("fib").ok_or(anyhow!("fib not found"))?;

        Ok(UpdateForwardMap {
            us_conn_map: MapHandle::try_from(us_conn_map)?,
            fib: MapHandle::try_from(fib)?,
        })
    }
}

impl Timer for UpdateForwardMap {
    fn trigger(&mut self) -> Result<()> {
        let mut states = HashMap::new();

        self.us_conn_map
            .lookup_batch(50, MapFlags::ANY, MapFlags::ANY)?
            .for_each(|(k, v)| {
                let k = align_val_to::<addr_key>(k.as_slice()).unwrap();
                let v = align_val_to::<us_conn_state>(v.as_slice()).unwrap();
                states.insert(k, v);
            });

        let pqueues = self
            .fib
            .lookup_batch(50, MapFlags::ANY, MapFlags::ANY)?
            .map(|(k, v)| {
                let k = align_val_to::<frwd_token>(k.as_slice()).unwrap();
                let v = align_val_to::<u32>(v.as_slice()).unwrap();
                (k, v)
            })
            .collect::<Vec<_>>();

        let key: [u8; 0] = [];
        for (ft, id) in pqueues.iter() {
            let queue = MapHandle::from_map_id(*id)?;
            let mut socks = Vec::new();

            while let Some(val) = queue.lookup(&key, MapFlags::empty())? {
                let val = align_val_to::<sock_key>(val.as_slice()).unwrap();
                socks.push(val);
            }

            if socks.is_empty() {
                continue;
            }

            socks.sort_by(|lhs, rhs| {
                let lhs_num_bytes = states
                    .get(&lhs.local)
                    .and_then(|s| Some(s.num_bytes))
                    .unwrap_or(0);
                let rhs_num_bytes = states
                    .get(&rhs.local)
                    .and_then(|s| Some(s.num_bytes))
                    .unwrap_or(0);

                lhs_num_bytes.cmp(&rhs_num_bytes)
            });

            let opts = libbpf_sys::bpf_map_create_opts {
                sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
                map_flags: libbpf_sys::BPF_ANY,
                // bpf_map_create_opts might have padding fields on some platform
                ..Default::default()
            };

            let new_queue = MapHandle::create(
                MapType::Queue,
                Some("fib_queue"),
                0,
                size_of::<sock_key>() as u32,
                2048,
                &opts,
            )?;

            for sock in socks.iter() {
                let value = unsafe { sock.as_bytes() };
                new_queue.update(&key, &value, MapFlags::ANY)?;
            }

            let key = unsafe { ft.as_bytes() };
            let val = new_queue.as_fd().as_raw_fd().to_ne_bytes();
            self.fib.update(&key, &val, MapFlags::EXIST)?;
        }

        Ok(())
    }
}

pub struct ConnectToBackend {
    config: Config,
}

impl ConnectToBackend {
    pub fn new(config: Config) -> Self {
        ConnectToBackend { config }
    }
}

impl NewUpstream for ConnectToBackend {
    fn new_upstream_connection(&mut self, ctx: &pipeline_ctx) -> Result<SocketAddr> {
        let ft = ctx.ft;
        if ft.direction != 2 {
            bail!("Invalid direction: {}", ft.direction);
        }

        let backend = format!("server{}", ft.backend);
        match self.config.select_backend_instance(&backend) {
            Some(addr) => Ok(*addr),
            None => bail!("Backend not found: {}", backend),
        }
    }
}
