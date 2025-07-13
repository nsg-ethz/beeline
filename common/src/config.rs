use rand::{self, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Config {
    pub socket: Option<SocketAddr>,
    pub proxy: Option<SocketAddr>,
    #[serde(default)]
    pub stats: bool,
    pub hosts: Vec<Host>,
    #[serde(default)]
    pub policies: Vec<Policy>,
    pub routes: Vec<Route>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Policy {
    pub name: String,
    pub method: Option<String>,
    pub path: Option<String>,
    pub dest_ip4: Option<IpAddr>,
    pub dest_port: Option<u16>,
    pub src_ip4: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub allow: bool,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Route {
    #[serde(alias = "match")]
    pub pattern: Pattern,
    pub dest: String,

    #[serde(default)]
    pub filters: Vec<Filter>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum Filter {
    #[serde(rename = "jwt")]
    Jwt(JwtFilter),

    #[serde(rename = "mutate")]
    Mutate(MutateFilter),
}

impl Filter {
    pub fn is_jwt(&self) -> bool {
        match self {
            Filter::Jwt(_) => true,
            _ => false,
        }
    }

    pub fn is_mutate(&self) -> bool {
        match self {
            Filter::Mutate(_) => true,
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct JwtFilter {
    pub secret: String,
    pub audience: Option<String>,
    pub issuer: Option<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct MutateFilter {
    pub add: Option<HashMap<String, String>>,
    pub remove: Option<Vec<String>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Pattern {
    pub path: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone, Default)]
pub struct Host {
    pub name: String,
    #[serde(default)]
    pub load_balancer: Option<LoadBalancer>,
    pub instances: Vec<SocketAddr>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum LoadBalancer {
    #[serde(rename = "ring")]
    Ring(RingLoadBalancer),
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct RingLoadBalancer {
    pub size: usize,
}

impl Config {
    pub fn resolve_host(&self, name: &str) -> Option<&Host> {
        self.hosts.iter().find(|host| host.name == *name)
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
