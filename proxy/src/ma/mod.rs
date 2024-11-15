use libbpf_rs::MapHandle;
use crate::bpf::types::*;
use std::collections::HashMap;

pub trait Timer: Send {

    fn trigger(&mut self, reads: &HashMap<String, MapHandle>, writes: &HashMap<String, MapHandle>);

    fn monitor_upstream(&mut self, key: &sock_key, ft: &frwd_token);
    fn monitor_downstream(&mut self, key: &sock_key);

}