#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1000);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

static __always_inline int _search(struct __sk_buff *skb, char* query, int query_len) {
    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;

    // int v;

    // bpf_for(v, 0, 5) {
    //     bpf_printk("X = %d", v);
    // }

    return -1;
}

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb) {
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb) {
    char* query = "HTTP/1.1";
    int j = _search(skb, query, 8);
    return 0;
}