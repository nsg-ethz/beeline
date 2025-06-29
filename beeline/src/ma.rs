use crate::bpf::types::*;
use anyhow::Result;
use common::Config;
use std::net::SocketAddr;

pub enum Action {
    Drop,
    Pass,
}

pub trait Pipeline: Sized {
    fn new(config: Config) -> Result<Self>;
    fn create_new_upstream(&mut self) -> Result<Box<dyn NewUpstream>>;
}

pub trait NewUpstream: Send + Sync {
    fn reverse_proxy_ft(&self) -> addr_key;
    fn all_upstream_fts(&self) -> Vec<addr_key>;
}
