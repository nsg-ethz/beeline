use serde::{Serialize, Deserialize};
use std::collections::HashMap;

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
    pub instances: Vec<String>,
}