use anyhow::{bail, Result};
use compose::*;
use libbpf_rs::skel::{
    OpenSkel, SkelBuilder
};
use std::os::fd::{AsFd, AsRawFd};

mod compose {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/parser.skel.rs"
    ));
}

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

fn main() -> Result<()> {
    let mut skel_builder = ParserSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    bump_memlock_rlimit()?;

    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;

    let sock_map_fd = skel.maps_mut()
        .sock_map()
        .as_fd()
        .as_raw_fd();

    skel
        .progs_mut()
        .bpf_prog_parser()
        .attach_sockmap(sock_map_fd)?;

    skel
        .progs_mut()
        .bpf_prog_verdict()
        .attach_sockmap(sock_map_fd)?;

    loop {}
}
