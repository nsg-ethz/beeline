use anyhow::{bail, Result};
use libbpf_rs::{libbpf_sys::bpf_program__attach_uprobe_opts, skel::{
    OpenSkel, Skel, SkelBuilder
}, UprobeOpts};
use uprobe::*;

mod uprobe {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/bpf/uprobe.skel.rs"
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
    let mut skel_builder = UprobeSkelBuilder::default();
    skel_builder.obj_builder.debug(true);

    bump_memlock_rlimit()?;

    let open_skel = skel_builder.open()?;
    let mut skel = open_skel.load()?;
    let mut progs = skel.progs_mut();
    let prog = progs.uprobe_read_req();

    let opts = UprobeOpts {
        retprobe: false,
        func_name: String::from("read_req"),
        ..Default::default()
    };

    let bin_path = "/local/home/laurinb/projs/l7-offload/exps/echo/proxy";
    prog.attach_uprobe_with_opts(653534, bin_path, 0, opts)?;

    loop {}
}
