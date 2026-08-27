# Beeline

Beeline is an eBPF-based fast path for L7 policy enforcement. Given an input policy, Beeline synthesizes a specialized data plane that can parse HTTP/1.1 and HTTP/2 messages and enforce various policies like JWT authorization, or header mutation.

## Project Structure

* `beeline`: source code for Beelines' control plane in Rust and data plane in eBPF
* `common`: general helpers used throughout the project
  * `common/bin/pol_gen.rs`: a binary that generates a Beeline or Envoy policy with a given set of parameters
  * `common/compiler.rs`: the Beeline data plane synthesis, added here for simplicity
* `config`: configuration files for Beeline and Envoy, used for the experiments and debugging
* `docker`: docker compose files for the experiments
* `echo`: an HTTP echo service, used in the Synthetic Servive Mesh
* `frontend`: an HTTP edge service, used in the Synthetic Servive Mesh
* `include/vmlinux.h`: the kernel headers for the current kernel version
* `k6`: the workloads used for the experiments
* `l4fp`: the L4 Fast Path, a simple eBPF program that redirects traffic at the socket level
* `scripts`: scripts used for the experiments
  * `scripts/exp` the experiments in a simple script. See below how to use them
  * `scripts/reload-lkm.sh` reloads the Linux kernel module that exposes the crypto API to eBPF
  * `scripts/stats.py` crawls GitHub and collects statistics on the usage of Envoy
  * `scripts/vis.py` visualizes experiment data
* `test`: the applications from [DeathStarBench](https://github.com/delimitrou/DeathStarBench). They include some bug fixes and configuration changes.

## Build

This project is tested and evaluated on Linux kernel version 6.16.
However, older versions should work as well if the `jwt` filter is disabled.
If you want to install kernel 6.16, make sure to set the `CONFIG_DEBUG_INFO_BTF="y"` config option before compiling.

Install the following packets:

```
sudo apt install autoconf autopoint binutils-dev bison clang-15 cmake dwarves flex libc6-dev-i386 libcap-dev libdwarf-dev libdw-dev libelf-dev libssl-dev llvm pkg-config python3-venv lua5.1 liblua5.1-dev unzip
cargo install jwt-cli
```

Note: depending on your kernel version, you'll have to install [dwarves](https://github.com/acmel/dwarves) from source.

Next, install [bpftool](https://github.com/libbpf/bpftool) from source.

Then, generate a new vmlinux file as follows:
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h
```

Finally, load the crypto kernel module that exposes the crypto API to eBPF:
```
./scripts/reload-lkm.sh
```
Check if the kfuncs have registered correctly. Consult [this tutorial](https://eunomia.dev/tutorials/features/struct_ops/) if an error occurs, .e.g, if `dmesg` logs "missing module BTF, cannot register kfunc".

You should now be able to compile and run Beeline as follows:

```
CONFIG=config/beeline/debug.yaml RUST_LOG=debug cargo run -p beeline
```

## Benchmarking

Before running any benchmark, make sure that the following requirements are met:
* The firewall allows traffic from the Docker network to reach the host. Explicitely enable this using the following rule: `sudo ufw allow from 172.18.0.0/24`
* The soft and hard limit of open files in `/etc/security/limits.conf` is high enough
* The `DEST_HOST` (in `script/bench.sh` and `script/pc.sh`) and `dest` in `k6/common.js` points to the machine that runs your application

The benchmarking scripts use the following terminology:
* `ms` stands for [Media Service](https://github.com/delimitrou/DeathStarBench/tree/master/mediaMicroservices)
* `sn` stands for [Social Network](https://github.com/delimitrou/DeathStarBench/tree/master/socialNetwork)
* `hr` stands for [Hotel Reservation](https://github.com/delimitrou/DeathStarBench/tree/master/hotelReservation)
* `ssm` stands for Synthetic Service Mesh.

Now, you can run the experiments and visualize them as follows:
```
# media service experiment
script/exp/fp-ms.sh -n [YOUR_EXPERIMENT_NAME] -f 1 -t [NUM_EPOCHS]
script/vis.py -n [YOUR_EXPERIMENT_NAME] rate
script/vis.py -n [YOUR_EXPERIMENT_NAME] cdf

# social network experiment
script/exp/fp-sn.sh -n [YOUR_EXPERIMENT_NAME] -f 1 -t [NUM_EPOCHS]
script/vis.py -n [YOUR_EXPERIMENT_NAME] rate
script/vis.py -n [YOUR_EXPERIMENT_NAME] cdf

# hotel reservation experiment
script/exp/fp-hr.sh -n [YOUR_EXPERIMENT_NAME] -f 1 -t [NUM_EPOCHS]
script/vis.py -n [YOUR_EXPERIMENT_NAME] rate
script/vis.py -n [YOUR_EXPERIMENT_NAME] cdf

# slow path experiment
script/exp/pc.sh -n [YOUR_EXPERIMENT_NAME] -p 0 -f 1 -t [YOUR_EXPERIMENT_NAME]
script/vis.py -n [YOUR_EXPERIMENT_NAME] complexity -p 0

# policy complexity experiment
script/exp/pc.sh -n [YOUR_EXPERIMENT_NAME] -f 1 -t [YOUR_EXPERIMENT_NAME]
script/vis.py -n [YOUR_EXPERIMENT_NAME] complexity -p [1,2,3 or 4]

# dissecting the policy 4
script/exp/pc.sh -n [YOUR_EXPERIMENT_NAME] -f 1 -t [YOUR_EXPERIMENT_NAME] -s k6/pc-rps.js
script/vis.py -n [YOUR_EXPERIMENT_NAME] dissect_complexity -p [1,2,3 or 4] -x [beeline, envoy_l4fp, or envoy]

# start the service mesh without generating load
PROXY_CONFIG=[BENCHMARK].yaml script/sm.sh up -c docker/[BENCHMARK]-[PROXY].yaml -n [YOUR_EXPERIMENT_NAME] -p [PROXY] -e [NUM_EPOCHS]

# for example to start the hotel reservation application with beeline
PROXY_CONFIG=hr.yaml script/sm.sh down -c docker/hr-beeline.yaml -n test -p beeline -e 1
```

To reproduce the policy statistics, run the following code:
```
GITHUB_API=[GITHUB_API_TOKEN] python3 script/stats.py search
python3 script/stats.py count -p res/stats/stats.json
script/vis.py stats
```


## Citation

If you use this library to conduct your own research, please cite the full paper as follows:
```
@misc{beeline,
      title={Enforcing Application-Layer Policies in eBPF}, 
      author={Laurin Brandner and Ayush Mishra and Sebastiano Miano and Aurojit Panda and Gianni Antichi and Laurent Vanbever},
      year={2026},
      eprint={2605.31084},
      archivePrefix={arXiv},
      primaryClass={cs.NI},
      url={https://arxiv.org/abs/2605.31084}, 
}
```
