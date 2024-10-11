use std::collections::HashMap;

use serde::{Serialize, Deserialize, };

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Host {
    pub name: String,
    pub address: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Route {
    pub r#match: HashMap<String, String>,

    // actions
    pub headers: Option<Headers>,
    pub destination: Option<Destination>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Headers {
    pub response: Option<HeaderModification>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct HeaderModification {
    pub add: HashMap<String, String>,
    pub remove: Vec<String>,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Destination {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    pub hosts: Vec<Host>,
    pub route: Vec<Route>,
}