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

static __always_inline int _search(struct __sk_buff *skb, char* query, __u16 query_len) {
    __u32 len = skb->len & 0xFFFF;
    if (bpf_skb_pull_data(skb, len) != 0) {
        return -1;
    }

    void* data = (void*)(long)skb->data;
    void* data_end = (void*)(long)skb->data_end;

    if (data + len > data_end || len < query_len) {
        return -1;
    }

    __u32 i = 0;
    bpf_for(i, 0, len-query_len) {
        if (data + i + query_len > data_end) {
            return -1;
        }

        if (__builtin_memcmp(data + i, query, query_len) == 0) {
            return i;
        }
    }

    return -1;
}

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb) {
    bpf_printk("Parsing %d bytes", skb->len);
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb) {
    char* query = "helloworld";
    bpf_printk("Search %s", query);

    int j = _search(skb, query, 9);
    if (j != -1) {
        bpf_printk("Found %s at %d", query, j);
    }

    return 0;
}