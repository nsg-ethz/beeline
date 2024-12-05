use anyhow::Result;
use libbpf_rs::MapHandle;
use crate::bpf::types::*;
use std::{collections::HashMap, net::SocketAddr};

pub enum Action {
    Drop,
    Pass
}

pub trait Pipeline: Sized {

    fn new(maps: HashMap<String, MapHandle>) -> Result<Self>;

    fn create_timers(&mut self) -> Result<Vec<Box<dyn Timer>>>;
    fn create_uturns(&mut self) -> Result<Vec<Box<dyn Uturn>>>;
    fn create_new_upstream(&mut self) -> Result<Box<dyn NewUpstream>>;

}

pub trait Timer: Send + Sync {

    fn trigger(&mut self) -> Result<()>;

    fn monitor_upstream(&mut self, key: &sock_key, ft: &frwd_token);
    fn monitor_downstream(&mut self, key: &sock_key);

}

pub trait Uturn: Send + Sync {

    fn handle_uturn(&mut self, ctx: &pipeline_ctx) -> Result<Action>;

}

pub trait NewUpstream: Send + Sync {

    fn new_upstream_connection(&mut self, ctx: &pipeline_ctx) -> Result<SocketAddr>;

}