#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1000);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb) {
    struct __sk_buff *ptr = NULL;
    ptr->len = skb->len;
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb) {
    return 0;
}