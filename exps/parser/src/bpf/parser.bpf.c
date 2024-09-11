#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

const __u32 s_init = 0;
const __u32 s_any = 1;

const __u32 a_match = 0xFFFFFFFF;
const __u32 a_done = 0xFFFFFFFE;

// these restrictions are needed to make the verifier happy
const __u32 MAX_BYTES = 0xFFFF;
const __u32 MAX_MATCHES = 0xFF;

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
} s2ts_mat SEC(".maps"), s2ts_mod SEC(".maps");

static __always_inline __u32 next_match_state(__u32 s, char input) {
    __u32* ts = bpf_map_lookup_elem(&s2ts_mat, &s);
    if (ts == NULL) {
        bpf_printk("Failed to find state %d", s);
        return s_any;
    }

    __u32* ns = bpf_map_lookup_elem(ts, &input);
    if (ns == NULL) {
        // check if there's a wildcard transition
        char wildcard = '*';
        ns = bpf_map_lookup_elem(ts, &wildcard);

        if (ns == NULL) {
            return s_any;   
        }
    }

    return *ns;
}

static __always_inline int _match(struct __sk_buff *skb) {
    __u32 len = skb->len & MAX_BYTES;
    if (bpf_skb_pull_data(skb, len) != 0) {
        return -1;
    }

    char* data = (char*)(long)skb->data;
    char* data_end = (char*)(long)skb->data_end;

    if (data + len > data_end || len == 0) {
        return -1;
    }

    __u32 s_mat = s_init;
    __u32 s_mod = s_init;
    __u32 num_matches = 0;
    __u32 i = 0;
    bpf_for(i, 0, len-1) {
        if (data + i + 1 > data_end) {
            return -1;
        }

        char c = data[i];

        s_mat = next_match_state(s_mat, c);

        switch (s_mat) {
            case a_match:
                bpf_printk("Match at %d", i);
                num_matches++;
                if (num_matches >= MAX_MATCHES) return num_matches;
                s_mat = s_any;
                break;
            case a_done:
                bpf_printk("Done at %d", i);
                return num_matches;
            case s_any:
                s_mat = next_match_state(s_any, c);
                break;
        }
    }

    return num_matches;
}

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb) {
    bpf_printk("Parsing %d bytes", skb->len);
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb) {
    if (_match(skb) == 2) {
        bpf_printk("Matched packet");
    }
    else {
        bpf_printk("Failed to match packet");
        return SK_PASS;
    }

    return 0;
}