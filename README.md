# Beeline

This project aims to bring L7 policy enforcement to the kernel, using eBPF.

## Testing

```
cargo test
```

## Benchmarking

It's likely that your firwall does not allow any traffic to reach host OS. Explicitely enable this using the following rule:
```
sudo ufw allow from 172.18.0.0/16
```

Also, you might have to increase the limit of open files in `/etc/security/limits.conf`

```
RUST_LOG=info taskset --cpu-list 1-35 cargo run -r -p beeline -- -a 172.17.0.1:9999 -c config/beeline/sn.yaml
docker compose -f docker/sn-beeline.yaml up --force-recreate
script/sm.sh -n [EXPERIMENT_NAME] -p beeline
```

## Requirements

This project is tested and evaluated on Linux kernel version 6.11.
However, older versions should work as well if the `jwt` filter is disabled.
If you want to install kernel 6.11, make sure to set the `CONFIG_DEBUG_INFO_BTF="y"` config option before compiling.

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
