use anyhow::Result;
use clap::Parser;
use libbpf_rs::{
    set_print, skel::{OpenSkel, SkelBuilder}, PrintLevel
};
use log::{
    debug,
    warn,
    info
};
use core::panic;
use std::{net::{IpAddr, SocketAddr}, os::{fd::{AsFd, AsRawFd, IntoRawFd}, unix::fs::OpenOptionsExt}, thread, time::Duration};

use dfa::{
    Action,
    http::HttpParser
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
    #[arg(short, long, default_value="127.0.0.1:8000")]
    address: String,

    #[arg(long="remove")]
    removals: Option<Vec<String>>,

    #[arg(long="rewrite")]
    rewrite: Option<Vec<String>>,
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

fn inject_parser(mut parser: HttpParser, skel: &mut parser::OpenParserSkel) -> Result<()> {
    // this is necessary so that the DFA won't
    // parse beyond the HTTP header
    parser.done_on_http_hdr_end()?;
    let mut num_matches = 0;

    for (from, to, input, action) in parser.iter_transitions() {
        if let Action::Match(_) = action {
            num_matches += 1;
        }

        let val = state_action_to_raw(*to, *action, skel.rodata());
        skel.rodata_mut().s2ts[*from as usize][*input as usize] = val;
    }

    for (cid, mo) in parser.modifications.iter() {
        let idx = *cid as usize;
        skel.rodata_mut().mods[idx].len = mo.replacement.len() as u8;
        skel.rodata_mut().mods[idx].tail = mo.tail;
        for (i, c) in mo.replacement.chars().enumerate() {
            skel.rodata_mut().mods[idx].str[i] = c as i8;
        }
    }

    skel.rodata_mut().num_matches = num_matches;

    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();
    set_print(Some((PrintLevel::Debug, print)));

    let args = Args::parse();
    let skel_builder = ParserSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;

    let mut parser = HttpParser::new(open_skel.rodata().s_init, open_skel.rodata().s_any);

    for hdr in args.removals.unwrap_or_default() {
        parser.remove_http_hdr(&hdr)?;
    }
    for hdr in args.rewrite.unwrap_or_default() {
        if let Some((key, val)) = hdr.split_once(":") {
            parser.rewrite_http_hdr(key.trim(), val.trim())?;
        }
        else {
            panic!("Invalid header format: {}", hdr);
        }
    }

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
