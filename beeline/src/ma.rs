use crate::bpf::types::*;
use anyhow::Result;
use common::Config;
use libbpf_rs::MapHandle;
use std::{collections::HashMap, net::SocketAddr};

pub enum Action {
    Drop,
    Pass,
}

pub trait Pipeline: Sized {
    fn new(config: Config, maps: HashMap<String, MapHandle>) -> Result<Self>;

    fn create_timers(&mut self) -> Result<Vec<Box<dyn Timer>>>;
    fn create_new_upstream(&mut self) -> Result<Box<dyn NewUpstream>>;
}

pub trait Timer: Send + Sync {
    fn trigger(&mut self) -> Result<()>;
}

pub trait NewUpstream: Send + Sync {
    fn new_upstream_connection(&mut self, ctx: &pipeline_ctx) -> Result<SocketAddr>;
}
