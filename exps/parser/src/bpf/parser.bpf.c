#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

const __u32 a_mask = 0xFFFF0000;
const __u32 s_mask = 0x0000FFFF;

const __u16 s_init = 0;
const __u16 s_any = 1;

const __u16 a_match = 1 << 15;
const __u16 a_done = 1 << 14;
const __u16 a_capture_start = 1 << 13;
const __u16 a_capture_end = 1 << 12;

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

static __always_inline void next(__u16 state, char input, __u16 *next_state, __u16 *action) {
    __u32 idx = state;
    __u32* ts = bpf_map_lookup_elem(&s2ts_mat, &idx);
    if (ts == NULL) {
        bpf_printk("Failed to find state %d", idx);
        *next_state = s_any;
        *action = 0;
        return;
    }

    __u32* sa = bpf_map_lookup_elem(ts, &input);
    if (sa == NULL) {
        // check if there's a wildcard transition
        char wildcard = '*';
        sa = bpf_map_lookup_elem(ts, &wildcard);

        if (sa == NULL) {
            *next_state = s_any;
            *action = 0;   
            return;
        }
    }

    *next_state = *sa & s_mask;
    *action = (*sa & a_mask) >> 16;
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

    __u16 s = s_init;

    __u32 num_matches = 0;
    __u32 cap_idx = 0;
    __u32 cap_len = 0;

    __u32 i = 0;
    bpf_for(i, 0, len-1) {
        if (data + i + 1 > data_end) {
            return -1;
        }

        __u16 a = 0;
        next(s, data[i], &s, &a);

        // bpf_printk("State %d, action %d", s, a);

        switch (a) {
        case a_match:
            bpf_printk("Match at %d", i);
            num_matches++;
            if (num_matches >= MAX_MATCHES) return num_matches;
            s = s_any;
            break;
        case a_done:
            bpf_printk("Done at %d", i);
            return num_matches;
        case a_capture_start:
            cap_idx = i;
            cap_len = 0;
            break;
        case a_capture_end:
            cap_len = i - cap_idx - 1;
            break;
        }

        // this means that we failed to match the current pattern
        // but maybe a new one starts now?
        if (s == s_any) {
            next(s_any, data[i], &s, &a);
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