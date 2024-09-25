use anyhow::{Context, Result};
use clap::Parser;
use libbpf_rs::{
    set_print, skel::{OpenSkel, SkelBuilder}, PrintLevel
};
use log::{
    debug,
    warn,
    info
};
use std::{net::ToSocketAddrs, os::{fd::{AsFd, AsRawFd, IntoRawFd}, unix::fs::OpenOptionsExt}, thread, time::Duration};

use matcher::{
    dfa::Action,
    http::HttpMatcher
};
use parser::*;

mod parser {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/parser.skel.rs"
    ));
}

#[derive(Parser)]
struct Args {
    #[arg(short, long)]
    destination: String,

    #[arg(long="remove")]
    removals: Option<Vec<String>>,
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

fn state_action_to_raw(state: u16, action: Action, rodata: &parser::parser_types::rodata) -> u32 {
    let action = match action {
        Action::Capture(cid) => {
            let raw_cid = (cid as u16) & rodata.a_cap_mask;
            if raw_cid != cid as u16 {
                panic!("Capture group id {} is too large, truncating to {}", cid, raw_cid);
            }
            raw_cid
        }
        Action::Match(cid) => {
            let raw_cid = (cid as u16) & rodata.a_cap_mask;
            if raw_cid != cid as u16 {
                panic!("Capture group id {} is too large, truncating to {}", cid, raw_cid);
            }

            rodata.a_match | (rodata.a_cap_mask & raw_cid)
        },
        Action::Done => rodata.a_done,
        Action::None => 0,
    };

    ((action as u32) << 16) | (state as u32)
}

fn inject_matcher(mut matcher: HttpMatcher, skel: &mut parser::OpenParserSkel) -> Result<()> {
    // this is necessary so that the DFA won't
    // parse beyond the HTTP header
    matcher.done_on_http_hdr_end()?;

    for (from, to, input, action) in matcher.dfa.iter_transitions() {
        let val = state_action_to_raw(*to, *action, skel.rodata());
        debug!("[{}, {}] = {}", from, input.escape_debug(), val);
        skel.rodata_mut().s2ts[*from as usize][*input as usize] = val;
    }

    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    set_print(Some((PrintLevel::Debug, print)));

    let args = Args::parse();
    let skel_builder = ParserSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;

    let mut matcher = HttpMatcher::new(open_skel.rodata().s_init, open_skel.rodata().s_any);
    // matcher.capture_http_hdr_val("content-length")?;
    // matcher.match_http_uri("/hello/world.html")?;
    for hdr in args.removals.unwrap_or_default() {
        matcher.remove_http_hdr(&hdr)?;
    }
    inject_matcher(matcher, &mut open_skel)?;

    let addr = args.destination.to_socket_addrs()?
        .next()
        .context("Failed to resolve destination address")?;
    open_skel.rodata_mut().PORT = addr.port() as u32;

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

    loop {
        thread::sleep(Duration::from_millis(200));   
    }
}
