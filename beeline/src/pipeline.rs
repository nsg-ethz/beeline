use crate::{bpf::types::*, ma::*};
use anyhow::{bail, Result};
use common::Config;
use std::{env, net::SocketAddr};

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
    fn reverse_proxy_ft(&self) -> addr_key {
        addr_key { ip4: 0, port: 0 } // "172.18.0.40:9999"
    }

    fn all_upstream_fts(&self) -> Vec<addr_key> {
        self.config
            .hosts
            .iter()
            .map(|h| addr_key::try_from(h.instances.first().unwrap()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap_or_default()
    }
}
