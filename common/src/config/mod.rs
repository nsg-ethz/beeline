use rand::{self, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, str::FromStr};

pub mod envoy;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub hosts: Vec<Host>,

    #[serde(alias = "parse")]
    pub patterns: Patterns,

    #[serde(alias = "authenticate")]
    pub auths: Vec<Authentication>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Patterns {
    pub http: HashMap<String, String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Authentication {
    pub name: String,
    pub secret: String,
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
        let mut hosts = Vec::new();
        for cluster in config.static_resources.clusters.iter() {
            let mut instances = Vec::new();
            for endpoint in cluster.load_assignment.endpoints.iter() {
                for endpoint in endpoint.lb_endpoints.iter() {
                    let addr = &endpoint.endpoint.address.socket_address;
                    let addr = format!("{}:{}", addr.address, addr.port_value);
                    instances.push(SocketAddr::from_str(&addr).unwrap());
                }
            }

            hosts.push(Host {
                name: cluster.name.clone(),
                instances,
            });
        }

        let mut patterns = HashMap::new();
        for listener in config.static_resources.listeners.iter() {
            for chains in listener.filter_chains.iter() {
                for filter in chains.filters.iter() {
                    for host in filter.typed_config.route_config.virtual_hosts.iter() {
                        for route in host.routes.iter() {
                            if route.r#match.prefix != "*" {
                                patterns.insert(String::from("path"), String::from("str"));
                            }
                        }
                        // for header in host.r#match.headers.iter() {
                        //     head
                        // }
                    }
                }
            }
        }

        Config {
            hosts,
            patterns: Patterns { http: patterns },
            ..Default::default()
        }
    }
}
