use crate::bpf::*;
use anyhow::Result;
use common::{
    config::beeline::Cidr,
    net::{get_gw_ip, TryIntoRawOctets},
};
use libbpf_rs::{
    set_print,
    skel::{OpenSkel, SkelBuilder},
    Link, PrintLevel,
};
use std::{
    mem::MaybeUninit,
    os::{
        fd::{AsFd, AsRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
};
use tracing::{debug, info, warn, Level};

pub mod bpf;

fn print(level: PrintLevel, msg: String) {
    let msg = msg.trim_start_matches("libbpf:").trim();

    match level {
        PrintLevel::Debug => debug!(target: "libbpf", "{}", msg),
        PrintLevel::Info => info!(target: "libbpf", "{}", msg),
        PrintLevel::Warn => warn!(target: "libbpf", "{}", msg),
    }
}

pub struct Proxy<'obj> {
    #[allow(dead_code)]
    skel: ProxySkel<'obj>,

    #[allow(dead_code)]
    sockops: Link,
}

unsafe impl<'obj> Send for Proxy<'obj> {}

unsafe impl<'obj> Sync for Proxy<'obj> {}

impl<'obj> Proxy<'obj> {
    pub fn accelerate(
        cidr: Cidr,
        open_obj: &'obj mut MaybeUninit<libbpf_rs::OpenObject>,
    ) -> Result<Self> {
        set_print(Some((PrintLevel::Debug, print)));

        let skel_builder = ProxySkelBuilder::default();
        let mut open_skel = skel_builder.open(open_obj)?;
        if tracing::event_enabled!(Level::DEBUG) {
            open_skel.progs.msg_verdict.set_log_level(1);
        }

        let addr_raw = cidr.addr.try_into_ne_octets()?;
        open_skel.maps.rodata_data.ip4_start = addr_raw;
        open_skel.maps.rodata_data.ip4_end = addr_raw + cidr.len();
        let gw_raw = get_gw_ip(cidr.addr).try_into_ne_octets()?;
        open_skel.maps.rodata_data.gw = gw_raw;

        let skel = open_skel.load()?;

        let sock_map_fd = skel.maps.sock_map.as_fd().as_raw_fd();

        let cgroup_fd = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY)
            .open("/sys/fs/cgroup")?
            .into_raw_fd();

        let sockops = skel.progs.monitor_sockets.attach_cgroup(cgroup_fd)?;

        skel.progs.msg_verdict.attach_sockmap(sock_map_fd)?;

        Ok(Self { skel, sockops })
    }
}
