use std::collections::HashMap;

use serde::{Serialize, Deserialize, };

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub hosts: Vec<Host>,
    pub spec: Spec,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Spec {
    pub http: Vec<Filter>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Filter {
    #[serde(alias = "match")]
    pub patterns: HashMap<String, String>,

    // actions
    pub headers: Option<Headers>,
    pub route: Vec<Route>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Headers {
    pub request: Option<HeaderModifications>,
    pub response: Option<HeaderModifications>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct HeaderModifications {
    pub add: Option<HashMap<String, String>>,
    pub remove: Option<Vec<String>>,
    pub set: Option<HashMap<String, String>>,
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