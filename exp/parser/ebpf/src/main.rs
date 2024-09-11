use anyhow::{bail, Context, Result};
use clap::Parser;
use libbpf_rs::{
    set_print, skel::{OpenSkel, SkelBuilder}, Map, MapFlags, MapHandle, MapType, PrintLevel
};
use log::{
    debug,
    warn,
    info
};
use std::{io::{Read, Write}, net::TcpListener, os::{fd::{AsFd, AsRawFd, IntoRawFd}, unix::fs::OpenOptionsExt}, mem::size_of
};

use matcher::{
    dfa::Action,
    http::HttpMatcher
};
use parser::*;

mod matcher;
mod parser {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/parser.skel.rs"
    ));
}

fn listen(sock_map: &mut Map) -> Result<()> {
    // start listening on port 8080
    let addr = "127.0.0.1:8080";
    let listener = TcpListener::bind(addr)?;
    info!("Listening on {}", addr);

    loop {
        let (mut stream, _) = listener.accept()?;
        let fd = stream.as_raw_fd();
        info!("Accepted connection {:?}", fd);

        // add socket to sockmap
        let key = 0u32.to_ne_bytes();
        let val = fd.to_ne_bytes();
        sock_map.update(&key, &val, MapFlags::ANY)?;

        let mut buf = [0; 256];
        loop {
            match stream.read(&mut buf) {
                Ok(_) => break,
                Err(_) => ()
            }
        }

        info!("Received data: {:?}", std::str::from_utf8(&buf).unwrap());

        let response = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nHello World!";
        stream.write(response.as_bytes())?;    
    }
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

fn create_state_bpf_map(state: u16, skel: &mut parser::ParserSkel) -> Result<MapHandle> {
    let opts = libbpf_sys::bpf_map_create_opts {
        sz: size_of::<libbpf_sys::bpf_map_create_opts>() as libbpf_sys::size_t,
        ..Default::default()
    };
    
    let idx = state as u32;
    let name = format!("t{}", idx);
    let map = MapHandle::create(MapType::Hash, Some(name), 1, 4, 256, &opts)
        .context("Failed to create map")?;
    let fd = map.as_fd().as_raw_fd();

    skel.maps()
        .s2ts_bpf()
        .update(&idx.to_ne_bytes(), &fd.to_ne_bytes(), MapFlags::ANY)
        .context("Failed to insert state into s2ts")?;

    Ok(map)
}

fn inject_matcher_bpf_map(mut matcher: HttpMatcher, skel: &mut parser::ParserSkel) -> Result<()> {
    // this is necessary so that the DFA won't
    // parse beyond the HTTP header
    matcher.done_on_http_hdr_end()?;

    let mut states = matcher.dfa.iter_states()
        .map(|s| s.clone())
        .collect::<Vec<_>>();

    states.sort();

    let mut tss = states.iter()
        .map (|idx| create_state_bpf_map(*idx, skel))
        .collect::<Result<Vec<_>>>()?;

    for (from, to, input, action) in matcher.dfa.iter_transitions() {
        let ts = tss.get_mut(*from as usize).unwrap();
        let key = (*input as u8).to_ne_bytes();

        let val = state_action_to_raw(*to, *action, &skel.rodata());
        let val = val.to_ne_bytes();
        ts.update(&key, &val, MapFlags::ANY)?;
    }

    Ok(())
}

fn inject_matcher_raw(mut matcher: HttpMatcher, skel: &mut parser::OpenParserSkel) -> Result<()> {
    // this is necessary so that the DFA won't
    // parse beyond the HTTP header
    matcher.done_on_http_hdr_end()?;

    for (from, to, input, action) in matcher.dfa.iter_transitions() {
        let val = state_action_to_raw(*to, *action, skel.rodata());
        debug!("[{}, {}] = {}", from, input.escape_debug(), val);
        skel.rodata_mut().s2ts_raw[*from as usize][*input as usize] = val;
    }

    Ok(())
}


fn main() -> Result<()> {
    env_logger::init();
    set_print(Some((PrintLevel::Debug, print)));

    let skel_builder = ParserSkelBuilder::default();
    let mut open_skel = skel_builder.open()?;

    let mut matcher = HttpMatcher::new(open_skel.rodata().s_init, open_skel.rodata().s_any);
    matcher.match_http_hdr("hallo", "welt")?;
    matcher.match_http_uri("/hello/world.html")?;
    matcher.remove_http_hdr("user-agent")?;
    inject_matcher_raw(matcher, &mut open_skel)?;

    let mut skel = open_skel.load()?;

    let sock_map_fd = skel
        .maps_mut()
        .sock_map()
        .as_fd()
        .as_raw_fd();

    let cgroup_fd = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open("/sys/fs/cgroup/")?
        .into_raw_fd();

    // not sure why we need to retain this link?
    let _sockops = skel.progs_mut()
        .sock_ops()
        .attach_cgroup(cgroup_fd)?;

    skel.progs_mut()
        .sock_ops()
        .attach_cgroup(cgroup_fd)?;

    skel.progs_mut()
        .stream_parser()
        .attach_sockmap(sock_map_fd)?;

    skel.progs_mut()
        .stream_verdict()
        .attach_sockmap(sock_map_fd)?;

    listen(skel.maps_mut().sock_map())?;
    Ok(())
}
