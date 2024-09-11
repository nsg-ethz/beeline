use anyhow::{bail, Result};
use libbpf_rs::{
    set_print, skel::{OpenSkel, SkelBuilder}, Map, MapFlags, PrintLevel
};
use log::{
    debug,
    warn,
    info
};
use std::{io::{Read, Write}, net::TcpListener, os::{fd::{AsFd, AsRawFd, IntoRawFd}, unix::fs::OpenOptionsExt}
};

use state_machine::StateMachine;
use parser::*;

mod dfa;
mod parser {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/parser.skel.rs"
    ));
}
mod state_machine;

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
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

fn main() -> Result<()> {
    env_logger::init();
    set_print(Some((PrintLevel::Debug, print)));

    bump_memlock_rlimit()?;

    let skel_builder = ParserSkelBuilder::default();
    let open_skel = skel_builder.open()?;
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

    skel.progs_mut()
        .sock_ops()
        .attach_cgroup(cgroup_fd)?;

    skel.progs_mut()
        .stream_parser()
        .attach_sockmap(sock_map_fd)?;

    skel.progs_mut()
        .stream_verdict()
        .attach_sockmap(sock_map_fd)?;

    let mut sm = StateMachine::new(&mut skel);
    sm.match_http_hdr("hallo", "welt")?;
    sm.match_http_uri("/hello/world.html")?;
    sm.remove_http_hdr("user-agent")?;
    sm.inject_dfa()?;

    listen(skel.maps_mut().sock_map())?;
    Ok(())
}
