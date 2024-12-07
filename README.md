# L7 Switch

This project has the aim of bringing L7 switching to the kernel, using eBPF.

## Testing

```
cargo test
```

## Benchmarking

```
./start-env.sh

script/bench.sh -u 1000 -s 1024 vu

./clean-env.sh
```

## Requirements

This project requires kernel version 6.11.
Install the following packets:

```
sudo apt install autoconf autopoint binutils-dev bison clang flex libc6-dev-i386 libcap-dev libelf-dev llvm pkg-config
```

Next, install [bpftool](https://github.com/libbpf/bpftool) from source.

Then, generate a new vmlinux file as follows:
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h
```
