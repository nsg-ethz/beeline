use anyhow::Result;
use crate::bpf::types::*;
use std::net::SocketAddr;

pub trait Timer: Send + Sync {

    fn trigger(&mut self) -> Result<()>;

    fn monitor_upstream(&mut self, key: &sock_key, ft: &frwd_token);
    fn monitor_downstream(&mut self, key: &sock_key);

}

pub trait Uturn: Send + Sync {

    fn handle_uturn(&self, ctx: &pipeline_ctx) -> Result<()>;

}

pub trait NewUpstream: Send + Sync {

    fn new_upstream_connection(&self, ctx: &pipeline_ctx) -> Result<SocketAddr>;

}