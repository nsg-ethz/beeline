#include "vmlinux.h"
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define LOG_LEVEL 2

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

char LICENSE[] SEC("license") = "GPL";

// these restrictions are needed to make the verifier happy
const __u16 MAX_BYTES = 0xFFFE;
const __u8 MAX_MATCHES = 0xF;
const __u8 MAX_MOD_LEN = 0xFF;

struct sock_key {
    __u32 local_ip4;
    __u32 local_port;
    __u32 remote_ip4;
    __u32 remote_port;
};

struct capture_group {
    __u16 id;
    __u16 idx;
    __u16 len;
};

struct modification {
    __u8 len;
    char str[MAX_MOD_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 2048);
    __uint(key_size, sizeof(struct sock_key));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

const __u32 a_mask = 0xFFFF0000;
const __u16 a_cap_mask = 0x000F;
const __u32 s_mask = 0x0000FFFF;

const __u16 s_init = 0;
const __u16 s_any = 1;

const __u16 a_match = 1 << 15;
const __u16 a_done = 1 << 14;

volatile const __u32 ip4;
volatile const __u32 port;
volatile const __u32 s2ts[128][256] = { s_init };
volatile const struct modification mods[MAX_MATCHES + 1] = { 0 };

static __always_inline void _skb_extract_key(struct __sk_buff *skb, struct sock_key *key) {
    key->remote_ip4 = skb->remote_ip4;
    key->local_ip4 = skb->local_ip4;
    key->remote_port = bpf_ntohl(skb->remote_port);
    key->local_port = skb->local_port;
}

static __always_inline void _msg_extract_key(struct sk_msg_md *msg, struct sock_key *key) {
    key->remote_ip4 = msg->remote_ip4;
    key->local_ip4 = msg->local_ip4;
    key->remote_port = bpf_ntohl(msg->remote_port);
    key->local_port = msg->local_port;
}

static __always_inline void _ops_extract_key(struct bpf_sock_ops *ops, struct sock_key *key) {
    key->remote_ip4 = ops->remote_ip4;
    key->local_ip4 = ops->local_ip4;
    key->remote_port = bpf_ntohl(ops->remote_port);
    key->local_port = ops->local_port;
}

static __always_inline void next(__u16 state, __u32 input, __u16 *next_state, __u16 *action) {
    state &= 0x7F;
    input &= 0xFF;

    __u32 sa = s2ts[state][input];
    if (sa == 0) {
        sa = s2ts[state]['*'];
        if (sa == 0) {
            *next_state = s_any;
            *action = 0;   
            return;
        }
    }

    *next_state = sa & s_mask;
    *action = (sa & a_mask) >> 16;
}

static __always_inline int _match(const struct sk_msg_md *msg, struct capture_group *cgs) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    __u32 len = (data_end - data) & MAX_BYTES;

    if (len == 0) {
        return 0;
    }
    
    __u16 s = s_init;
    __u32 num_matches = 0;
    __u32 cap_idx[MAX_MATCHES] = { 0 };

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
                cgs[num_matches] = (struct capture_group) {
                    .id = cid,
                    .idx = cap_idx[cid],
                    .len = i - cap_idx[cid] + 1
                };
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

    bpf_log("WARN: Parsed entire payload (%dB)", len);

    return num_matches;
}

static __always_inline int _modify(struct sk_msg_md *msg, const struct capture_group *cg) {
    __u16 len = cg->len;
    __u16 idx = cg->idx;

    if (len > MAX_BYTES) return -1;
    len &= 0xFF;

    if (idx > MAX_BYTES) return -1;
    idx &= 0xFFF;

    if (cg->id >= MAX_MATCHES) return -1;
    volatile const struct modification *mod = &mods[cg->id & 7]; // TODO: why do we have to truncate cg->id here?

    __s32 diff = mod->len - len;

    bpf_log("Increasing msg size by %d (%d-%d)", diff, mod->len, len);
    if (diff > 0) {
        bpf_msg_push_data(msg, idx, diff, 0);
    }
    else if (diff < 0) {
        bpf_msg_pop_data(msg, idx, -diff, 0);
    }

    bpf_log("Rewriting payload in range [%d, %d]", idx, len);

    if (bpf_msg_pull_data(msg, idx, idx+mod->len, 0) < 0) return -1;

    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    
    __u16 i;
    bpf_for(i, 0, mod->len) {
        if (data + i + 1 > data_end) break;
        data[i] = mod->str[i];
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

    bpf_log("Verdict %d [%pI4:%u->%pI4:%u]", r, &key.local_ip4, key.local_port, &key.remote_ip4, key.remote_port);

    return r;
}

SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    // we're only processing the respoonse for now
    if (msg->local_port == port) {
        bpf_log("Processing %dB msg", msg->size);

        struct capture_group cgs[MAX_MATCHES] = { 0 };
        if (_match(msg, cgs) == 1) {
            if (_modify(msg, &cgs[0]) < 0) {
                bpf_err("ERROR: Modifying message failed.");
            }
        }
    }

    return _try_redirect(msg);
}

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ctx) {
    struct sock_key key = { 0 };
    _ops_extract_key(ctx, &key);

    // if (key.local_ip4 != key.remote_ip4) return SK_PASS;

    if ((key.local_ip4 == ip4 && key.local_port == port) || (key.remote_ip4 == ip4 && key.remote_port == port)) {
    // if (key.local_port == 3000 || key.remote_port == 3000 || key.local_port == 8000 || key.remote_port == 8000) {
        if (ctx->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ctx->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
            __u32 tmp = key.local_port;
            key.local_port = key.remote_port;
            key.remote_port = tmp;     

            tmp = key.local_ip4;
            key.local_ip4 = key.remote_ip4;
            key.remote_ip4 = tmp;   

            if (bpf_sock_hash_update(ctx, &sock_map, &key, BPF_NOEXIST) < 0) {
                bpf_err("ERROR: Adding socket failed.");
            }
            else {
                bpf_log("Added socket [%pI4:%u->%pI4:%u]", &key.local_ip4, key.local_port, &key.remote_ip4, key.remote_port);
            }
        }
    }

    return SK_PASS;
}
