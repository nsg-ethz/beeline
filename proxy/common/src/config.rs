use std::collections::HashMap;

use serde::{Serialize, Deserialize, };

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub hosts: Vec<Host>,
    pub spec: Spec,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Spec {
    pub hosts: Vec<String>,
    pub http: Vec<Filter>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Filter {
    #[serde(alias = "match")]
    pub patterns: HashMap<String, String>,

    // actions
    #[serde(alias = "headers")]
    pub header_mods: Option<HeaderModification>,
    pub route: Option<Vec<Route>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct HeaderModification {
    pub response: Option<ResponseModification>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseModification {
    pub add: Option<HashMap<String, String>>,
    pub remove: Option<Vec<String>>,
    pub rewrite: Option<HashMap<String, String>>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub name: String,
    pub address: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Route {
    pub destination: Destination
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}