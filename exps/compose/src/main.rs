use anyhow::{bail, Result};
use libbpf_rs::{skel::{
    OpenSkel, Skel, SkelBuilder
}, TcHookBuilder};
use uprobe::*;

mod uprobe {
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
    let mut progs = skel.progs_mut();
    let parser = progs.bpf_prog_parser();
    parser.attach()?;

    let verdict = progs.bpf_prog_verdict();
    verdict.attach()?;

    loop {}
}
