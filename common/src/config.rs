use serde::{Deserialize, Serialize};
use std::{collections::HashMap, net::SocketAddr};

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
