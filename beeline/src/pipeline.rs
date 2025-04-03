use crate::{bpf::types::*, ma::*};
use anyhow::{bail, Ok, Result};
use common::Config;
use std::{
    hash::{Hash, Hasher},
    net::SocketAddr,
};

impl Eq for frwd_token {}

impl PartialEq for frwd_token {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
            && self.direction == other.direction
            && self.path == other.path
            && self.num_bytes_min == other.num_bytes_min
    }
}

impl Hash for frwd_token {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
        self.direction.hash(state);
        self.path.hash(state);
        self.num_bytes_min.hash(state);
    }
}

pub struct DebugPipeline {
    config: Config,
}

impl Pipeline for DebugPipeline {
    fn new(config: Config) -> Result<Self> {
        Ok(DebugPipeline { config })
    }

    fn create_new_upstream(&mut self) -> Result<Box<dyn NewUpstream>> {
        Ok(Box::new(ConnectToBackend {
            config: self.config.clone(),
        }))
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
    fn reverse_proxy_ft(&self) -> frwd_token {
        frwd_token {
            direction: 3,
            path: 0,
            addr: addr_key { ip4: 0, port: 0 },
            num_bytes_min: 1,
            padding: 0,
        }
    }

    fn all_upstream_fts(&self) -> Vec<frwd_token> {
        self.config
            .hosts
            .iter()
            .enumerate()
            .map(|(idx, _)| frwd_token {
                direction: 2,
                path: (idx + 1) as u8,
                addr: addr_key { ip4: 0, port: 0 },
                num_bytes_min: 1,
                padding: 0,
            })
            .collect::<Vec<_>>()
    }

    fn new_upstream_connection(&mut self, ft: &frwd_token) -> Result<SocketAddr> {
        match ft.direction {
            2 => {
                let name = match ft.path {
                    1 => "social-graph-service",
                    2 => "home-timeline-service",
                    3 => "compose-post-service",
                    4 => "post-storage-service",
                    5 => "user-timeline-service",
                    6 => "url-shorten-service",
                    7 => "user-service",
                    8 => "media-service",
                    9 => "text-service",
                    10 => "unique-id-service",
                    11 => "user-mention-service",
                    _ => bail!("Invalid path {}", ft.path),
                };
                match self.config.select_backend_instance(&name) {
                    Some(addr) => Ok(*addr),
                    None => bail!("Backend not found: {}", name),
                }
            }
            3 => Ok("172.18.0.40:9999".parse()?),
            // 3 => Ok("127.0.0.1:8000".parse()?),
            _ => bail!("Invalid direction: {}", ft.direction),
        }
    }
}
