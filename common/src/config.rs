use rand::{self, seq::SliceRandom};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr};

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
