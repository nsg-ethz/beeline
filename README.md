# L7 Offload

A load balancing experiment forked from [ebpf-http-offload](https://github.com/sebymiano/ebpf-http-offload).

## Benchmarking

```
./start-env.sh

cd ebpf
./start-proxy.sh

script/bench -n new_benchmark -p ebpf -s "1024 2048 4096"

./clean-env.sh
```

## Resources

* [What are best practices for benchmarking Envoy?](https://www.envoyproxy.io/docs/envoy/latest/faq/performance/how_to_benchmark_envoy)
* [gRPC Demystified – Protobuf Encoding](https://dfordebugging.wordpress.com/2023/02/17/grpc-demystified-protobuf-encoding/)
* [Protocol Buffer Documentation](https://protobuf.dev/programming-guides/encoding/)


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