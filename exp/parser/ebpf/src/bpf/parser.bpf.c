#include "vmlinux.h"
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define LOG_LEVEL 1

#if LOG_LEVEL == 0
#define bpf_log(...) (0)
#define bpf_err(...) (0)
#elif LOG_LEVEL == 1
#define bpf_log(...) (0)
#define bpf_err(...) bpf_printk(__VA_ARGS__)
#elif LOG_LEVEL == 2
#define bpf_log(...) bpf_printk(__VA_ARGS__)
#define bpf_err(...) bpf_printk(__VA_ARGS__)
#endif

extern int bpf_dynptr_from_skb(struct __sk_buff *skb, u64 flags, struct bpf_dynptr *ptr__uninit) __ksym;
extern void *bpf_dynptr_slice(const struct bpf_dynptr *ptr, u32 offset, void *buffer__opt, u32 buffer__szk) __ksym;
extern __u32 bpf_dynptr_size(const struct bpf_dynptr *ptr) __ksym;

char LICENSE[] SEC("license") = "GPL";

// these restrictions are needed to make the verifier happy
const __u32 MAX_BYTES = 0xFFFE;
const __u32 MAX_MATCHES = 20;

volatile const __u32 PORT;

const __u32 a_mask = 0xFFFF0000;
const __u16 a_cap_mask = 0x000F;
const __u32 s_mask = 0x0000FFFF;

const __u16 s_init = 0;
const __u16 s_any = 1;

const __u16 a_match = 1 << 15;
const __u16 a_done = 1 << 14;

volatile const __u8 use_raw_stm = 1;
volatile const __u32 s2ts_raw[128][256] = { s_init };

struct sock_key {
    __u32 local_ip4;
    __u32 local_port;
    __u32 remote_ip4;
    __u32 remote_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 1000);
    __uint(key_size, sizeof(struct sock_key));
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
} s2ts_bpf SEC(".maps");

static __always_inline void _skb_extract_key(struct __sk_buff *skb, struct sock_key *key) {
    key->remote_ip4 = bpf_ntohl(skb->remote_ip4);
    key->local_ip4 = bpf_ntohl(skb->local_ip4);
    key->remote_port = bpf_ntohl(skb->remote_port);
    key->local_port = skb->local_port;
}

static __always_inline void _msg_extract_key(struct sk_msg_md *msg, struct sock_key *key) {
    key->remote_ip4 = bpf_ntohl(msg->remote_ip4);
    key->local_ip4 = bpf_ntohl(msg->local_ip4);
    key->remote_port = bpf_ntohl(msg->remote_port);
    key->local_port = msg->local_port;
}

static __always_inline void _ops_extract_key(struct bpf_sock_ops *ops, struct sock_key *key) {
    key->remote_ip4 = bpf_ntohl(ops->remote_ip4);
    key->local_ip4 = bpf_ntohl(ops->local_ip4);
    key->remote_port = bpf_ntohl(ops->remote_port);
    key->local_port = ops->local_port;
}

static __always_inline void next_bpf(__u16 state, char input, __u16 *next_state, __u16 *action) {
    __u32 idx = state;
    __u32* ts = bpf_map_lookup_elem(&s2ts_bpf, &idx);
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

static __always_inline void next_raw(__u16 state, __u32 input, __u16 *next_state, __u16 *action) {
    state &= 0x7F;
    input &= 0xFF;

    __u32 sa = s2ts_raw[state][input];
    if (sa == 0) {
        sa = s2ts_raw[state]['*'];
        if (sa == 0) {
            *next_state = s_any;
            *action = 0;   
            return;
        }
    }

    *next_state = sa & s_mask;
    *action = (sa & a_mask) >> 16;
}

static __always_inline void next(__u16 state, char input, __u16 *next_state, __u16 *action) {
    if (use_raw_stm) {
        next_raw(state, input, next_state, action);
    }
    else {
        next_bpf(state, input, next_state, action);
    }
}

static __always_inline int _match(const struct sk_msg_md *msg, __u32 *cg_idx, __u32 *cg_len) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    __u32 len = (data_end - data) & MAX_BYTES;

    if (len == 0) {
        return 0;
    }
    
    __u16 s = s_init;
    __u32 num_matches = 0;
    __u32 cap_idx[16] = { 0 };

    __u32 i;
    bpf_for(i, 0, len) {
        if (data + i + 1 > data_end) break;
        char c = data[i];

        __u16 a = 0;
        __u16 s_old = s;
        next(s, c, &s, &a);
        __u16 cid = a & a_cap_mask;

        if ((a & a_match) != 0) {
            bpf_log("Match %d in [%d, %d]", cid, cap_idx[cid], i - cap_idx[cid] + 1);
            if (num_matches < MAX_MATCHES) {
                cg_idx[num_matches] = cap_idx[cid];
                cg_len[num_matches] = i - cap_idx[cid] + 1;
            }

            num_matches++;
            if (num_matches >= MAX_MATCHES) return num_matches;
            s = s_any;
        }
        else if ((a & a_done) != 0) {
            bpf_log("Done matching at %d", i);
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

static __always_inline int _modify(const struct sk_msg_md *msg, __u16 idx, __u16 len) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;

    if (len > MAX_BYTES) return -1;
    len &= 0xFFF;

    if (idx > MAX_BYTES) return -1;
    idx &= 0xFFF;
    
    __u16 i;
    bpf_for(i, idx, idx+len) {
        if (data + i + 1 > data_end) break;

        data[i] = 'X';
    }

    return 0;
}

static __always_inline int _try_redirect(struct sk_msg_md *msg) {
    struct sock_key key = { 0 };
    _msg_extract_key(msg, &key);

    int r = bpf_msg_redirect_hash(msg, &sock_map, &key, BPF_F_INGRESS);
    if (r == SK_DROP) {
        bpf_err("ERROR: Redirect failed");
    }

    bpf_log("Verdict %d [%pI4:%u->%pI4:%u]", r, key.local_ip4, key.local_port, key.remote_ip4, key.remote_port);

    return r;
}

SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    __u32 cg_idx[MAX_MATCHES] = { 0 };
    __u32 cg_len[MAX_MATCHES] = { 0 };

    bpf_log("Processing %dB msg", msg->size);

    if (_match(msg, cg_idx, cg_len) != 1) {
        return SK_PASS;
    }

    bpf_log("Matched packet. Captured [%d, %d]", cg_idx[0], cg_len[0]);
    _modify(msg, cg_idx[0]+5, cg_len[0]-6);

    return SK_PASS;
}

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ctx) {
    struct sock_key key = { 0 };
    _ops_extract_key(ctx, &key);

    if (key.local_port != PORT) {
        return SK_PASS;
    }

    if (ctx->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ctx->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        if (bpf_sock_hash_update(ctx, &sock_map, &key, BPF_NOEXIST) < 0) {
            bpf_err("ERROR: Adding socket failed.");
        }

        bpf_log("Added socket [%pI4:%u->%pI4:%u]", key.local_ip4, key.local_port, key.remote_ip4, key.remote_port);
    }

    return SK_PASS;
}
