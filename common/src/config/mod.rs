use rand::{self, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr};

mod envoy;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub hosts: Vec<Host>,

    #[serde(alias = "parse")]
    pub patterns: Patterns,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Patterns {
    pub http: HashMap<String, String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Host {
    pub name: String,
    pub instances: Vec<SocketAddr>,
}

impl Config {
    pub fn resolve_instance(&self, backend: &str, instance: u16) -> Option<&SocketAddr> {
        self.hosts
            .iter()
            .find(|host| host.name == *backend)
            .and_then(|host| host.instances.iter().find(|addr| addr.port() == instance))
    }

    pub fn select_backend_instance(&self, backend: &str) -> Option<&SocketAddr> {
        self.all_backend_instances(backend)?
            .choose(&mut rand::thread_rng())
    }

    pub fn all_backend_instances(&self, backend: &str) -> Option<&Vec<SocketAddr>> {
        let host = self.hosts.iter().find(|host| host.name == *backend)?;

        Some(&host.instances)
    }
}

impl From<envoy::Config> for Config {
    fn from(config: envoy::Config) -> Self {
        let hosts = Vec::new();

        // for cluster in config.clusters {
        //     hosts.push(Host { name, instances });
        // }

        Config {
            hosts,
            patterns: Patterns::default(),
        }
    }
}
