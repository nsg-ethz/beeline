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

First, install the following packets:

```
sudo apt install llvm clang libc6-dev-i386 linux-tools-common linux-tools-`uname -r`
```

For some tests, it's necessary to raise the limit for open files of the root user (since that user is running the systemd tasks).
This can be done by following [this question](https://unix.stackexchange.com/a/443467) or by modifying `/etc/security/limits.conf`.

Then, generate a new vmlinux file as follows:
```
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ./vmlinux.h
```