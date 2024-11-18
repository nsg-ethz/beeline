use anyhow::Result;
use crate::bpf::types::*;
use std::net::SocketAddr;

pub enum Action {
    Drop,
    Pass
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