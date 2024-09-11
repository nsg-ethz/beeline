#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

const __u32 s_init = 0;
const __u32 s_match = 0xFFFFFFFF;

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1000);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

struct trans {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __uint(key_size, sizeof(char));
    __uint(value_size, sizeof(__u32));
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __array(values, struct trans);
} s2ts SEC(".maps");

static __always_inline __u32 next_state(__u32 s, char input) {
    __u32* ts = bpf_map_lookup_elem(&s2ts, &s);
    if (ts == NULL) {
        bpf_printk("Failed to find state %d", s);
        return s_init;
    }

    __u32* ns = bpf_map_lookup_elem(ts, &input);
    if (ns == NULL) {
        return s_init;
    }

    return *ns;
}

static __always_inline int _search(struct __sk_buff *skb) {
    __u32 len = skb->len & 0xFFFF;
    if (bpf_skb_pull_data(skb, len) != 0) {
        return -1;
    }

    char* data = (char*)(long)skb->data;
    char* data_end = (char*)(long)skb->data_end;

    if (data + len > data_end || len == 0) {
        return -1;
    }

    __u32 s = s_init;
    __u32 i = 0;
    bpf_for(i, 0, len-1) {
        if (data + i + 1 > data_end) {
            return -1;
        }

        char c = data[i];
        __u32 s_old = s;
        s = next_state(s, c);
        bpf_printk("%d - %c -> %d", s_old, c, s);
        if (s == s_match) {
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
    int j = _search(skb);
    if (j != -1) {
        bpf_printk("Found hello header at %d", j);
    }

    return 0;
}