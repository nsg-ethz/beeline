#include "vmlinux.h"
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#ifdef LOG_LEVEL
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
#else
    #define bpf_log(...) (0)
    #define bpf_err(...) (0)
#endif

char LICENSE[] SEC("license") = "GPL";

// these restrictions are needed to make the verifier happy
const __u16 MAX_BYTES = 0xFFFE;
const __u8 MAX_MATCHES = 16;
const __u8 MAX_MATCH_MASK = 15;
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
    __u8 tail;
};

struct filter {
    __u8 num_matches;
    __u8 num_modifications;
    __u8 mids[MAX_MATCHES];
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 2048);
    __uint(key_size, sizeof(struct sock_key));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

const __u32 a_mask = 0xFFFF0000;
const __u16 a_match = 1 << 15;
const __u16 a_done = 1 << 14;
const __u16 a_start_capture = 1 << 13;
const __u16 a_end_capture = 1 << 12;
// if a_match -> then this represents the fid
// if a_done -> then this is 0
// if a_start_capture or a_end_capture -> then this is the mid
const __u16 a_id_mask = 0x00FF;

const __u32 s_mask = 0x0000FFFF;
const __u16 s_init = 0;
const __u16 s_any = 1;

volatile const __u32 ip4;
volatile const __u32 port;
volatile const __u32 s2ts[128][256] = { s_init };
volatile const struct modification mods[MAX_MATCHES] = { 0 };
volatile const struct filter filters[MAX_MATCHES] = { 0 };

struct capture_group cgs[MAX_MATCHES] = { 0 };
// this is internal to the _parse function
__u32 mod_idx[MAX_MATCHES] = { 0 };
__u32 fid_cnt[MAX_MATCHES] = { 0 };

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

static __always_inline int _parse(const struct sk_msg_md *msg) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    __u32 len = (data_end - data) & MAX_BYTES;

    if (len == 0) {
        return 0;
    }
    
    __u16 s = s_init;

    memset(cgs, 0, sizeof(cgs));
    memset(mod_idx, 0, sizeof(mod_idx));
    memset(fid_cnt, 0, sizeof(fid_cnt));

    __u32 i;
    bpf_for(i, 0, len) {
        if (data + i + 1 > data_end) return -1;
        char c = data[i];

        __u16 a = 0;
        __u16 s_old = s;
        next(s, c, &s, &a);

        // it should never happen that any of these cases are true simultaneously
        // but it makes the verifier happy when we don't use else if here
        if ((a & a_start_capture) != 0) {
            __u16 mid = a & a_id_mask & MAX_MATCH_MASK;
            mod_idx[mid] = i;
        }
        if ((a & a_end_capture) != 0) {
            __u16 mid = a & a_id_mask & MAX_MATCH_MASK;
            bpf_log("Captured range %d in [%d, %d]", mid, mod_idx[mid], i - mod_idx[mid] + 1);

            cgs[mid] = (struct capture_group) {
                .id = mid,
                .idx = mod_idx[mid],
                .len = i - mod_idx[mid] + 1
            };
        }
        if ((a & a_match) != 0) {
            __u16 fid = a & a_id_mask & MAX_MATCH_MASK;
            bpf_log("Matched filter %d at %d", fid, i);
            fid_cnt[fid]++;
        }
        if ((a & a_done) != 0) {
            bpf_log("Done parsing at %d", i);
            return 0;
        }

        // this means that we failed to match the current pattern
        // but maybe a new one starts now?
        if (s == s_any) {
            next(s_any, c, &s, &a);
        }
    }

    bpf_log("WARN: Parsed entire payload (%dB)", len);

    return 0;
}

static __always_inline int _log_msg_range(struct sk_msg_md *msg, __u16 idx, __u16 len) {
    if (bpf_msg_pull_data(msg, idx, idx+len, 0) < 0) return -1;

    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;

    __u16 j;
    bpf_for(j, 0, len) {
        if (data + j + 1 > data_end) return -1;
        bpf_log("data[%d]=%c", idx+j, data[j]);
    }
}

static __always_inline int _modify(struct sk_msg_md *msg, const struct capture_group *cg, __s16 *diff) {
    // in case something fails, we don't want to resport a wrong diff
    if (diff == NULL) return -1;
    *diff = 0;

    __u16 len = cg->len;
    __u16 idx = cg->idx;

    if (len > MAX_BYTES) return -1;
    len &= 0xFF;

    if (idx > MAX_BYTES) return -1;
    idx &= 0xFFF;

    if (cg->id >= MAX_MATCHES) return -1;
    volatile const struct modification *mod = &mods[cg->id];

    len -= mod->tail;
    __s16 delta = mod->len - len;

    bpf_log("Increasing msg size by %d (%d-%d) at %d (mid: %d)", delta, mod->len, len, idx, cg->id);

    // we first have to linearize the data
    // TODO: figure out if we have to pull the data for every single modification
    if (bpf_msg_pull_data(msg, 0, idx+mod->len, 0) < 0) return -1;

    if (delta > 0) {
        if (bpf_msg_push_data(msg, idx, delta, 0) < 0) return -1;
    }
    else if (delta < 0) {
        if (bpf_msg_pop_data(msg, idx, -delta, 0) < 0) return -1;
    }

    // we don't set diff until we actually resized the message
    *diff = delta;

    // we're done if we don't have to write anything
    if (mod->len == 0) return 0;

    bpf_log("Rewriting payload (%dB) in range [%d, %d]", msg->size, idx, len);

    // at this point we have to pull the data again to get valid data pointers    
    if (bpf_msg_pull_data(msg, idx, idx+mod->len, 0) < 0) return -1;

    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    
    __u16 i;
    bpf_for(i, 0, mod->len) {
        if (data + i + 1 > data_end) return -1;
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

        if (_parse(msg) == 0) {
            // parsing was successful, check if we have a match
            __u8 i;
            __u16 no_match = 0xFFFF;
            __u16 fid = no_match;
            // TODO: why -1 here??
            bpf_for(i, 0, MAX_MATCHES-1) {
                if (fid_cnt[i] == filters[i].num_matches && filters[i].num_matches > 0) {
                    fid = i;
                    break;
                } 
            }

            // we have a match, apply the filter's actions
            if (fid != no_match) {
                fid &= MAX_MATCH_MASK;

                bpf_log("Apply filter %d (matches: %d, modifications: %d)", fid, filters[fid].num_matches, filters[i].num_modifications);
                
                __s16 off = 0;
                __s16 until = 0;
                bpf_for(i, 0, filters[fid].num_modifications) {
                    __s16 mid = filters[fid].mids[i] & MAX_MATCH_MASK;
                    bpf_log("Apply modification %d (fid: %d)", mid, fid);

                    cgs[mid].idx += off;
                    until = cgs[mid].idx + cgs[mid].len;

                    __s16 diff = 0;
                    if (_modify(msg, &cgs[mid], &diff) < 0) {
                        bpf_err("ERROR: Modifying message failed.");
                        break;
                    }

                    off += diff;
                }
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
