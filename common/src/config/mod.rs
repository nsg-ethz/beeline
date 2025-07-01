use crate::config::envoy::HttpFilter;
use rand::{self, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr, str::FromStr};

pub mod envoy;

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub proxy: Option<SocketAddr>,
    pub hosts: Vec<Host>,
    pub routes: Vec<Route>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Route {
    #[serde(alias = "match")]
    pub pattern: Pattern,
    pub dest: String,

    #[serde(default)]
    pub filters: Vec<HashMap<String, String>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Pattern {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
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

        let mut routes = Vec::new();
        for listener in config.static_resources.listeners.iter() {
            for chains in listener.filter_chains.iter() {
                for filter in chains.filters.iter() {
                    let http_filters = filter
                        .typed_config
                        .http_filters
                        .iter()
                        .map(|f| match f {
                            HttpFilter::Jwt(filter) => {
                                let mut jwt = HashMap::new();
                                jwt.insert("type".to_string(), "jwt".to_string());
                                if let Some(issuer) =
                                    &filter.typed_config.providers.first().unwrap().issuer
                                {
                                    jwt.insert("issuer".to_string(), issuer.to_string());
                                }
                                if let Some(audiences) =
                                    &filter.typed_config.providers.first().unwrap().audiences
                                {
                                    jwt.insert(
                                        "audience".to_string(),
                                        audiences.first().unwrap().to_string(),
                                    );
                                }

                                Some(jwt)
                            }
                            HttpFilter::Unsupported => None,
                        })
                        .filter(|f| f.is_some())
                        .map(|f| f.unwrap())
                        .collect::<Vec<_>>();

                    for host in filter.typed_config.route_config.virtual_hosts.iter() {
                        for route in host.routes.iter() {
                            let mut pattern = Pattern::default();

                            if route.r#match.prefix != "*" {
                                pattern.path = Some(route.r#match.prefix.clone());
                            }
                            let headers: HashMap<String, String> = route
                                .r#match
                                .headers
                                .iter()
                                .map(|h| (h.name.to_string(), h.string_match["exact"].clone()))
                                .collect();
                            if headers.len() > 0 {
                                pattern.headers = Some(headers);
                            }

                            routes.push(Route {
                                pattern,
                                dest: route.route.cluster.clone(),
                                filters: http_filters.clone(),
                            });
                        }
                    }
                }
            }
        }

        Config {
            proxy: None,
            hosts,
            routes,
        }
    }
}
