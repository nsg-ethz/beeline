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
    fn reverse_proxy_ft(&self) -> frwd_token;
    fn all_upstream_fts(&self) -> Vec<frwd_token>;
    fn new_upstream_connection(&mut self, ft: &frwd_token) -> Result<SocketAddr>;
}
