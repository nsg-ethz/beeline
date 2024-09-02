#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb) {
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb) {
    return 0;
}