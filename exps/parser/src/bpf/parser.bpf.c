#include "vmlinux.h"
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

extern int bpf_dynptr_from_skb(struct __sk_buff *skb, u64 flags, struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, u32 offset, void *buffer__opt, u32 buffer__szk) __ksym;
extern __u32 bpf_dynptr_size(const struct bpf_dynptr *ptr) __ksym;

char LICENSE[] SEC("license") = "GPL";

// these restrictions are needed to make the verifier happy
const __u32 MAX_BYTES = 0xFFFF;
const __u32 MAX_MATCHES = 20;

// volatile const __u32 TEST = 10;

const __u32 a_mask = 0xFFFF0000;
const __u16 a_cap_mask = 0x000F;
const __u32 s_mask = 0x0000FFFF;

const __u16 s_init = 0;
const __u16 s_any = 1;

const __u16 a_match = 1 << 15;
const __u16 a_done = 1 << 14;

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
} s2ts_mat SEC(".maps");

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

static __always_inline int _match(const struct bpf_dynptr *ptr, __u32 *cg_idx, __u32 *cg_len) {
    __u32 len = bpf_dynptr_size(ptr) & MAX_BYTES;
    __u16 s = s_init;
    __u32 num_matches = 0;
    __u32 cap_idx[16] = { 0 };

    __u32 i;
    bpf_for(i, 0, len) {
        char c;
        bpf_dynptr_slice(ptr, i, &c, 1);

        __u16 a = 0;
        __u16 s_old = s;
        next(s, c, &s, &a);
        __u16 cid = a & a_cap_mask;

        if ((a & a_match) != 0) {
            bpf_printk("Match %d in [%d, %d]", cid, cap_idx[cid], i - cap_idx[cid] + 1);
            if (num_matches < MAX_MATCHES) {
                cg_idx[num_matches] = cap_idx[cid];
                cg_len[num_matches] = i - cap_idx[cid] + 1;
            }

            num_matches++;
            if (num_matches >= MAX_MATCHES) return num_matches;
            s = s_any;
        }
        else if ((a & a_done) != 0) {
            bpf_printk("Done matching");
            return num_matches;
        }

        cap_idx[cid] = i;

        // this means that we failed to match the current pattern
        // but maybe a new one starts now?
        if (s == s_any) {
            next(s_any, c, &s, &a);
        }
    }

    return num_matches;
}

static __always_inline int _modify(const struct bpf_dynptr *ptr, __u16 idx, __u16 len) {
    __u16 i;
    bpf_for(i, idx, idx+len) {
        char x = 'X';
        bpf_dynptr_write(ptr, i, &x, 1, BPF_F_RECOMPUTE_CSUM);
    }

    return 0;
}

SEC("sk_skb/stream_parser")
int stream_parser(struct __sk_buff *skb) {
    bpf_printk("Parsing %d bytes", skb->len);
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int stream_verdict(struct __sk_buff *skb) {
    __u32 cg_idx[MAX_MATCHES] = { 0 };
    __u32 cg_len[MAX_MATCHES] = { 0 };

    struct bpf_dynptr ptr;
    bpf_dynptr_from_skb(skb, 0, &ptr);

    if (_match(&ptr, cg_idx, cg_len) != 3) {
        return SK_PASS;
    }

    bpf_printk("Matched packet. Captured [%d, %d]", cg_idx[2], cg_len[2]);
    _modify(&ptr, cg_idx[2], cg_len[2]);

    return SK_PASS;
}

// SEC("custom/stream_modifier")
// int stream_modifier(struct __sk_buff *skb) {

//     return SK_PASS;
// }

SEC("sockops")
int sock_ops(struct bpf_sock_ops *ops) {
    int op = (int)ops->op;

    bpf_printk("sockops | local: %d, remote: %d", ops->local_port, bpf_ntohl(ops->remote_port));
    __u32 key = ops->local_port;

    bpf_sock_ops_cb_flags_set(ops, ops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
    if (bpf_sock_hash_update(ops, &sock_map, &key, BPF_NOEXIST) < 0) {
        bpf_printk("ERROR: Adding socket failed.");
    }

    return 0;
}