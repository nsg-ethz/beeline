# L7 Offload

A load balancing experiment forked from [ebpf-http-offload](https://github.com/sebymiano/ebpf-http-offload).

## Benchmarking

```
./start-env.sh

cd ebpf
./start-proxy.sh

script/bench -n new_benchmark -p ebpf

./clean-env.sh
```

## Resources

* [What are best practices for benchmarking Envoy?](https://www.envoyproxy.io/docs/envoy/latest/faq/performance/how_to_benchmark_envoy)


## Dependencies

```
sudo apt install llvm clang libc6-dev-i386 linux-tools-common linux-tools-`uname -r`
```