use anyhow::Result;
use clap::Parser;
use common::{
    config::Config,
    parse::{Action, http::HttpParser}
};
use libbpf_rs::{
    set_print, skel::{OpenSkel, SkelBuilder}, PrintLevel
};
use log::{
    debug,
    warn,
    info,
    log_enabled
};
use core::panic;
use std::{collections::HashMap, net::{IpAddr, SocketAddr}, os::{fd::{AsFd, AsRawFd, IntoRawFd}, unix::fs::OpenOptionsExt}, thread, time::Duration};

use proxy::*;

mod proxy {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/proxy.skel.rs"
    ));
}

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value="127.0.0.1:8000")]
    address: String,

    #[arg(short, long, default_value="config/debug.yaml")]
    config: String,
}

fn print(level: PrintLevel, msg: String) {
    let msg = msg.trim_start_matches("libbpf:")
        .trim();

    match level {
        PrintLevel::Debug => debug!(target: "libbpf", "{}", msg),
        PrintLevel::Info => info!(target: "libbpf", "{}", msg),
        PrintLevel::Warn => warn!(target: "libbpf", "{}", msg),
    }
}

fn state_action_to_raw(state: u16, action: Action, rodata: &proxy::proxy_types::rodata) -> u32 {
    let action = match action {
        Action::StartCapture(mid) => {
            rodata.a_start_capture | (mid as u16) & rodata.a_id_mask
        },
        Action::EndCapture(cid, mid) => {
            let id = (cid as u16) << 6 | (mid as u16);
            rodata.a_end_capture | id & rodata.a_id_mask
        }
        Action::Match(fid) => {
            rodata.a_match | (fid as u16) & rodata.a_id_mask
        },
        Action::Done => rodata.a_done,
        Action::None => 0,
    };

    ((action as u32) << 16) | (state as u32)
}

fn inject_parser(parser: HttpParser, skel: &mut proxy::OpenProxySkel) -> Result<()> {
    for (from, to, input, action) in parser.iter_transitions() {
        let val = state_action_to_raw(*to, *action, skel.rodata());
        skel.rodata_mut().s2ts[*from as usize][*input as usize] = val;
    }

    for (mid, mo) in parser.modifications.iter() {
        let idx = *mid as usize;
        skel.rodata_mut().mods[idx].len = mo.replacement.len() as u8;
        skel.rodata_mut().mods[idx].tail = mo.tail;
        for (i, c) in mo.replacement.chars().enumerate() {
            skel.rodata_mut().mods[idx].str[i] = c as i8;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    set_print(Some((PrintLevel::Debug, print)));

    let args = Args::parse();
    let config = std::fs::File::open(args.config)?;
    let config: Config = serde_yaml::from_reader(config)?;

    let skel_builder = ProxySkelBuilder::default();
    let mut open_skel = skel_builder.open()?;
    if log_enabled!(log::Level::Debug) {
        open_skel.progs_mut().msg_verdict().set_log_level(1)?;
    }

    let mut parser = HttpParser::new(open_skel.rodata().s_init, open_skel.rodata().s_any);
    let mut mods = HashMap::new();

    for filter in config.spec.http {
        let fid = parser.start_new_filter() as usize;

        for (key, val) in &filter.patterns {
            parser.match_http_hdr(&key, &val)?;
        }

        let mut num_mods = 0;
        if let Some(headers) = filter.header_mods {
            if let Some(res) = headers.response {
                if let Some(remove) = res.remove {
                    for key in remove {
                        // a modification must be unique, otherwise dfa complains
                        let mid = mods.get(&key).copied().unwrap_or_else(|| {
                            parser.remove_http_hdr(&key).expect("Failed to add remove header pattern")
                        });
                        
                        mods.insert(key, mid);
                        open_skel.rodata_mut().filters[fid].mids[num_mods] = mid;
                        num_mods += 1;
                    }
                }
            }
        }

        debug!("filter {}: {} matches, {} modifications", fid, filter.patterns.len(), num_mods);

        open_skel.rodata_mut().filters[fid].num_matches = filter.patterns.len() as u8;
        open_skel.rodata_mut().filters[fid].num_modifications = num_mods as u8;
    }

    // this is necessary so that the DFA won't
    // parse beyond the HTTP header
    parser.done_on_http_hdr_end()?;

    inject_parser(parser, &mut open_skel)?;

    let addr: SocketAddr = args.address.parse()?;
    if let IpAddr::V4(ip) = addr.ip() {
        open_skel.rodata_mut().ip4 = u32::from_ne_bytes(ip.octets());
    }
    else {
        panic!("IPv6 is not supported");
    }

    open_skel.rodata_mut().port = addr.port() as u32;

    let mut skel = open_skel.load()?;

    let sock_map_fd = skel.maps()
        .sock_map()
        .as_fd()
        .as_raw_fd();

    let cgroup_fd = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open("/sys/fs/cgroup")?
        .into_raw_fd();

    let _sockops = skel.progs_mut()
        .monitor_sockets()
        .attach_cgroup(cgroup_fd)?;

    skel.progs_mut()
        .msg_verdict()
        .attach_sockmap(sock_map_fd)?;

    info!("Ready");

    loop {
        thread::sleep(Duration::from_millis(200));   
    }
}
