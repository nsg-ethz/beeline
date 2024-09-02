# load-balancing

A load balancing experiment forked from [ebpf-http-offload](https://github.com/sebymiano/ebpf-http-offload).

## Benchmarking

```
./start-env.sh

cd naive
./start-proxy.sh

fortio load -n [NUM_REQS] -c [CONCURRENCY] -qps [QUERIES_PER_SECOND] 127.0.0.1:3000/server1

PAYLOAD_SIZE=128 taskset --cpu-list 2-8 k6 run --summary-export=test.json bench/stress.js 

./clean-env.sh
```

Some documentation on performance testing:
* [What are best practices for benchmarking Envoy?](https://www.envoyproxy.io/docs/envoy/latest/faq/performance/how_to_benchmark_envoy)

## Requirements
```
go install fortio.org/fortio@latest
```
