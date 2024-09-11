use anyhow::{bail, Result};
use libbpf_rs::{skel::{
    OpenSkel, SkelBuilder
}, Map, MapFlags};
use std::{collections::HashMap, net::TcpListener, os::fd::{AsFd, AsRawFd}};

use state_machine::StateMachine;
use parser::*;

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
    let listener = TcpListener::bind("127.0.0.1:8080")?;
    let mut streams = HashMap::new();

    loop {
        let (stream, _) = listener.accept()?;
        let fd = stream.as_raw_fd();
        println!("Accepted connection {:?}", fd);

        // add socket to sockmap
        let key = 0u32.to_ne_bytes();
        let val = fd.to_ne_bytes();
        sock_map.update(&key, &val, MapFlags::ANY)?;

        streams.insert(stream.as_raw_fd(), stream);
    }
}

fn main() -> Result<()> {
    let mut skel_builder = ParserSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    bump_memlock_rlimit()?;

    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;

    let sock_map_fd = skel
        .maps_mut()
        .sock_map()
        .as_fd()
        .as_raw_fd();

    skel.progs_mut()
        .bpf_prog_parser()
        .attach_sockmap(sock_map_fd)?;

    skel.progs_mut()
        .bpf_prog_verdict()
        .attach_sockmap(sock_map_fd)?;

    let mut sm = StateMachine::new(&mut skel)?;
    sm.match_http_hdr_field("hello".into(), "world".into())?;

    listen(skel.maps_mut().sock_map())?;
    Ok(())
}
