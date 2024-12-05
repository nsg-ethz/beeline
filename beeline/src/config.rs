use std::collections::HashMap;
use serde::{Serialize, Deserialize };

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Config {
    pub hosts: Vec<Host>,
    pub spec: Spec,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Spec {
    #[serde(alias = "parse")]
    pub patterns: Patterns,

    #[serde(alias = "forward")]
    pub routes: Vec<Route>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Patterns {
    pub http: HashMap<String, String>,
}


#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Route {
    pub predicates: HashMap<String, String>,
    pub destination: Destination
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Host {
    pub name: String,
    pub address: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize, Clone)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}