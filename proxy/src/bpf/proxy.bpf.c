#include "vmlinux.h"
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#ifndef bpf_clamp_uminmax
#define bpf_clamp_uminmax(VAR, UMIN, UMAX)                                                         \
    asm volatile("if %0 >= %[min] goto +2\n"                                                       \
                 "%0 = %[min]\n"                                                                   \
                 "goto +2\n"                                                                       \
                 "if %0 <= %[max] goto +1\n"                                                       \
                 "%0 = %[max]\n"                                                                   \
                 : "+r"(VAR)                                                                       \
                 : [min] "i"(UMIN), [max] "i"(UMAX))
#endif

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

// these restrictions are needed to make the verifier happy
#define MAX_BYTES 0xFFFE
#define MAX_MATCHES 16
#define MAX_MATCH_MASK 15
#define MAX_MOD_LEN 0xFF

char LICENSE[] SEC("license") = "GPL";

struct addr_key {
    u32 ip4;
    u32 port;
};

struct sock_key {
    struct addr_key local;
    struct addr_key remote;
};

struct prange {
    u16 idx;
    u16 len;
};

struct modification {
    u8 len;
    char str[MAX_MOD_LEN];
    u8 tail;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, int);
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct addr_key);
    __type(value, struct opt_frwd_token);
} sock_wait_list SEC(".maps");

// TODO: These per-cpu maps are only necessary if the respective struct 
// doesn't fit onto the stack
// TODO: percpu maps might also be necessary for forwarding and auth tokens
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct pipeline_ctx);
} ctx_percpu SEC(".maps");

const u32 a_mask = 0xFFFF0000;
const u16 a_match = 1 << 15;
const u16 a_done = 1 << 14;
const u16 a_start_capture = 1 << 13;
const u16 a_end_capture = 1 << 12;
// if a_match -> then this represents the fid
// if a_done -> then this is 0
// if a_start_capture -> then this is the cid
// if a_end_capture -> then this is cid | mid
const u16 a_id_mask = 0x0FFF;
const u16 a_id_1_mask = 0x0FC0;
const u16 a_id_2_mask = 0x003F;

const u32 s_mask = 0x0000FFFF;
const u16 s_init = 0;
const u16 s_any = 1;

volatile const u32 ip4;
volatile const u32 port;
const u32 local_port = 12345;
const u32 local_gw = 254;
volatile const u32 s2ts[128][256];
volatile const struct modification mods[MAX_MATCHES] = { 0 };
const u32 percpu_key = 0;

enum pr_action {
    PR_DROP=0,
    PR_PASS,
    PR_UTRN
};

// TODO: this needs special care to get aligned
// user generated
struct frwd_token {
    u32 conn_id;
    u8 direction;
    u8 backend;
    u8 num_bytes_min;
};

// ----------------------------------------------
// compiler generated

struct pipeline_ctx {
    char backend[4096];
    u32 backend_len;
    char authorization[4096];
    u32 authorization_len;
    u32 content_length;
    u32 conn_id;
    struct frwd_token ft;
};

enum ft_direction {
    PR_DOWNSTREAM = 1,
    PR_UPSTREAM
};

enum ft_backend {
    PR_SERVER1 = 1,
    PR_SERVER2 = 2,
    PR_SERVER3 = 3,
    PR_SERVER4 = 4
};

static __always_inline void _init_pipeline_ctx(struct sk_msg_md *msg, const struct prange *pranges, struct pipeline_ctx *ctx) {
    char *data = (char *)(long)msg->data;
    char buf[64]; // a number cannot be larger than 64 bytes
    unsigned long tmp = 0;

    struct prange r0 = pranges[0];
    u32 r0_len = r0.len & 4095;
    bpf_probe_read_kernel(ctx->backend, r0_len, data + r0.idx);
    ctx->backend_len = r0_len;

    struct prange r1 = pranges[1];
    u32 r1_len = r1.len & 4095;
    bpf_probe_read_kernel(ctx->authorization, r1_len, data + r1.idx);
    ctx->authorization_len = r1_len;

    struct prange r2 = pranges[2];
    u32 r2_len = r2.len & 62;
    bpf_probe_read_kernel(buf, r2_len, data + r2.idx);
    buf[r2_len] = '\0'; // this way, we don't need an if-clause
    bpf_strtoul(buf, r2_len + 1, 10, &tmp);
    ctx->content_length = tmp;

    struct prange r3 = pranges[3];
    u32 r3_len = r3.len & 62;
    bpf_probe_read_kernel(buf, r3_len, data + r3.idx);
    buf[r3_len] = '\0'; // this way, we don't need an if-clause
    bpf_strtoul(buf, r3_len + 1, 10, &tmp);
    ctx->conn_id = tmp;
}

// ----------------------------------------------
// user provided

struct ds_conn_state {
    u32 num_bytes;
    u32 num_reqs;
    u64 last_req_ts;
    u64 this_req_ts;
};

struct us_conn_state {
    u32 num_bytes;
    u32 num_reqs;
};

// compiler generated
struct opt_frwd_token {
    u8 is_some;
    struct frwd_token inner;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 2048);
    __type(key, struct sock_key);
    __type(value, struct pipeline_ctx);
} utrn_wait_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, struct ds_conn_state);
} ds_conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct addr_key);
    __type(value, struct us_conn_state);
} us_conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, char[4096]);
    __type(value, u8);
} auth_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct frwd_token);
    __type(value, struct sock_key);
} frwd_map SEC(".maps");

enum pr_action authorize(const struct sk_msg_md* msg, struct pipeline_ctx *ctx) {
    u8 *verified = bpf_map_lookup_elem(&auth_map, ctx->authorization);
    if (*verified == NULL) return PR_UTRN;
    if (*verified == 0) return PR_DROP;

    return PR_PASS;
}

enum pr_action update_ds_state(const struct sock_key *dkey, struct pipeline_ctx *ctx) {
    struct ds_conn_state *s = bpf_map_lookup_elem(&ds_conns, dkey);
    if (s == NULL) {
        struct ds_conn_state ns = (struct ds_conn_state) {
            .num_bytes = ctx->content_length,
            .num_reqs = 1,
            .last_req_ts = 0,
            .this_req_ts = bpf_ktime_get_ns()
        };
        bpf_map_update_elem(&ds_conns, dkey, &ns, BPF_ANY);
    }
    else {
        s->num_bytes += ctx->content_length;
        s->num_reqs++;
        s->last_req_ts = s->this_req_ts;
        s->this_req_ts = bpf_ktime_get_ns();
    }

    return PR_PASS;
}

enum pr_action update_us_state(const struct sock_key *ukey, struct pipeline_ctx *ctx) {
    const struct addr_key *rukey = &ukey->remote;
    struct us_conn_state *s = bpf_map_lookup_elem(&us_conns, rukey);
    if (s == NULL) {
        struct us_conn_state ns = (struct us_conn_state) {
            .num_bytes = ctx->content_length,
            .num_reqs = 1,
        };
        bpf_map_update_elem(&us_conns, rukey, &ns, BPF_ANY);
    }
    else {
        s->num_bytes += ctx->content_length;
        s->num_reqs++;
    }

    return PR_PASS;
}

enum pr_action forward_ds_conn(const struct sock_key *dkey, struct pipeline_ctx *ctx) {
    if (dkey == NULL || ctx == NULL) {
        return PR_DROP;
    }

    // rate limit connection if it's sent a request less than 1ms ago
    // u64 req_interval = state->this_req_ts - state->last_req_ts;
    // if (req_interval < 10000000) {
    //     return SK_DROP;
    // }

    const char *server1 = "server1";
    bool backend_is_server1 = bpf_strncmp(ctx->backend, 7, server1) == 0;
    const char *server2 = "server2";
    bool backend_is_server2 = bpf_strncmp(ctx->backend, 7, server2) == 0;
    const char *server3 = "server3";
    bool backend_is_server3 = bpf_strncmp(ctx->backend, 7, server3) == 0;
    const char *server4 = "server4";
    bool backend_is_server4 = bpf_strncmp(ctx->backend, 7, server4) == 0;

    if (!backend_is_server1 && !backend_is_server2 && !backend_is_server3 && !backend_is_server4) {
        return PR_DROP;
    }

    if (backend_is_server1) ctx->ft.backend = PR_SERVER1;
    if (backend_is_server2) ctx->ft.backend = PR_SERVER2;
    if (backend_is_server3) ctx->ft.backend = PR_SERVER3;
    if (backend_is_server4) ctx->ft.backend = PR_SERVER4;

    ctx->ft.direction = PR_UPSTREAM;
    ctx->ft.num_bytes_min = true;

    // at this point we have to ask the plugin how it wants to route
    // this request back to the client
    struct frwd_token ft_inv = { 0 };
    ft_inv.direction = PR_DOWNSTREAM;
    ft_inv.conn_id = ctx->conn_id;

    if (bpf_map_update_elem(&frwd_map, &ft_inv, dkey, BPF_ANY) < 0) {
        bpf_err("ERROR: Failed to set downstream forwarding token");
    }
    else {
        bpf_log("Set downstream forwarding token [%pI4:%u->%pI4:%u]", &dkey->local.ip4, dkey->local.port, &dkey->remote.ip4, dkey->remote.port);
    }
    
    return PR_PASS;
}

enum pr_action forward_us_conn(const struct sock_key *ukey, struct pipeline_ctx *ctx) {
    ctx->ft.direction = PR_DOWNSTREAM;
    ctx->ft.conn_id = ctx->conn_id;

    return PR_PASS;
}

enum pr_action select_sock(const struct sock_key *ikey, struct pipeline_ctx *ctx, struct sock_key **ekey) {
    *ekey = bpf_map_lookup_elem(&frwd_map, &ctx->ft);
    if (*ekey == NULL) return PR_UTRN;

    return PR_PASS;
}   

// ----------------------------------------------

static __always_inline void _next(u16 state, u32 input, u16 *next_state, u16 *action) {
    state &= 0x7F;
    input &= 0xFF;

    u32 sa = s2ts[state][input];
    if (sa == 0) {
        sa = s2ts[state]['*'];
        bpf_clamp_uminmax(sa, 0, 0xFFFFFFFF);
        if (sa == 0) {
            *next_state = s_any;
            *action = 0;   
            return;
        }
    }

    *next_state = sa & s_mask;
    *action = (sa & a_mask) >> 16;
}

static __always_inline int _parse_from(const struct sk_msg_md *msg, u32 start, struct prange *pranges, bool *pmatches, u32* cidx) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    u32 len = ((u32)(data_end - data) - start) & MAX_BYTES;

    if (len == 0) {
        return 0;
    }

    u16 s = s_init;
    u32 i;
    bpf_for(i, 0, len) {
        if (data + i + 1 > data_end) return -1;
        char c = data[i];

        u16 a = 0;
        _next(s, c, &s, &a);

        // it should never happen that any of these cases are true simultaneously
        // but it makes the verifier happy when we don't use else if here
        if ((a & a_start_capture) != 0) {
            u16 cid = a & a_id_mask & MAX_MATCH_MASK;
            bpf_log("Start capture range (%d, ?) in [%d, ...]", cid, i);
            cidx[cid] = i;
        }
        if ((a & a_end_capture) != 0) {
            u16 cid = ((a & a_id_1_mask) >> 6) & MAX_MATCH_MASK;
            u16 rid = a & a_id_2_mask & MAX_MATCH_MASK;
            bpf_log("End capture range (%d, %d) in [%d, %d]", cid, rid, cidx[cid], i - cidx[cid] + 1);

            pranges[rid] = (struct prange) {
                .idx = cidx[cid],
                .len = i - cidx[cid] + 1
            };
            cidx[cid] = 0;
        }
        if ((a & a_match) != 0) {
            u16 mid = a & a_id_mask & MAX_MATCH_MASK;
            bpf_err("Match %d at %d", mid, i);
            pmatches[mid] = true;
        }
        if ((a & a_done) != 0) {
            bpf_log("Done parsing at %d", i);
            return 0;
        }

        // this means that we failed to match the current pattern
        // but maybe a new one starts now?
        if (s == s_any) {
            _next(s_any, c, &s, &a);
        }
    }

    return -1;
}

static __always_inline int _parse(struct sk_msg_md *msg, struct prange *pranges, bool *pmatches) {
    u32 cidx[MAX_MATCHES] = { 0 };
    int res = _parse_from(msg, 0, pranges, pmatches, cidx);

    // TODO: Ideally, we would do this in a loop until we have consumed the whole header
    if (res < 0) {
        u32 old_end = (long)msg->data_end - (long)msg->data;
        u32 new_end = 4096 > msg->size ? msg->size : 4096;

        bpf_msg_pull_data(msg, 0, new_end, 0);
        res = _parse_from(msg, old_end, pranges, pmatches, cidx);
    }

    return res;
}

static __always_inline int _log_msg_range(struct sk_msg_md *msg, u16 idx, u16 len) {
    if (bpf_msg_pull_data(msg, idx, idx+len, 0) < 0) return -1;

    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;

    u16 j;
    bpf_for(j, 0, len) {
        if (data + j + 1 > data_end) return -1;
        bpf_log("data[%d]=%c", idx+j, data[j]);
    }

    return 0;
}

static __always_inline int _modify(struct sk_msg_md *msg, const struct prange *r, volatile const struct modification *m, __s16 *diff) {
    // in case something fails, we don't want to resport a wrong diff
    if (diff == NULL) return -1;
    *diff = 0;

    u16 len = r->len;
    u16 idx = r->idx;

    if (len > MAX_BYTES) return -1;
    len &= 0xFF;

    if (idx > MAX_BYTES) return -1;
    idx &= 0xFFF;

    len -= m->tail;
    __s16 delta = m->len - len;

    bpf_log("Increasing msg size by %d (%d-%d) at %d", delta, m->len, len, idx);

    // we first have to linearize the data
    // TODO: figure out if we have to pull the data for every single modification
    if (bpf_msg_pull_data(msg, 0, idx+m->len, 0) < 0) return -1;

    if (delta > 0) {
        if (bpf_msg_push_data(msg, idx, delta, 0) < 0) return -1;
    }
    else if (delta < 0) {
        if (bpf_msg_pop_data(msg, idx, -delta, 0) < 0) return -1;
    }

    // we don't set diff until we actually resized the message
    *diff = delta;

    // we're done if we don't have to write anything
    if (m->len == 0) return 0;

    bpf_log("Rewriting payload (%dB) in range [%d, %d]", msg->size, idx, len);

    // at this point we have to pull the data again to get valid data pointers    
    if (bpf_msg_pull_data(msg, idx, idx+m->len, 0) < 0) return -1;

    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    
    u16 i;
    bpf_for(i, 0, m->len) {
        if (data + i + 1 > data_end) return -1;
        data[i] = m->str[i];
    }

    return 0;
}

// compile-time generated
static __always_inline enum pr_action _pipeline(struct sk_msg_md *msg, struct pipeline_ctx *ctx, const struct sock_key *ikey) {
    bool is_downstream = (ikey->remote.ip4 == ip4 && ikey->remote.port == port);

    enum pr_action res = authorize(msg, ctx);
    if (res == PR_DROP) {
        bpf_log("PLUGIN: Drop downstream msg");
        return PR_DROP;
    }

    if (is_downstream) {
        if (update_ds_state(ikey, ctx) != PR_PASS) {
            bpf_err("ERROR: Updating downstream connection state failed.");
        }

        if (ctx->backend_len == 0) return PR_DROP;
        enum pr_action res = forward_ds_conn(ikey, ctx);
        if (res == PR_DROP) {
            bpf_log("PLUGIN: Drop downstream msg");
            return PR_DROP;
        }
    }
    else {
        struct us_conn_state state = { 0 };
        if (update_us_state(ikey, ctx) != PR_PASS) {
            bpf_err("ERROR: Updating upstream connection state failed.");
        }

        enum pr_action res = forward_us_conn(ikey, ctx);
        if (res == PR_DROP) {
            bpf_log("PLUGIN: Drop upstream msg");
            return PR_DROP;
        }
    }

    return PR_PASS;
}

SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    // socket identifeir of the ingress connection
    struct sock_key ikey = {
        .local = {
            .ip4 = msg->local_ip4,
            .port = msg->local_port
        },
        .remote = {
            .ip4 = msg->remote_ip4,
            .port = bpf_ntohl(msg->remote_port)
        }
    };

    bool is_downstream = (ikey.remote.ip4 == ip4 && ikey.remote.port == port);
    bool is_local_gw = ((ikey.local.ip4 >> 24) & 0xFF) == local_gw || ikey.local.ip4 == ip4;
    bool is_retry = !is_downstream && ikey.local.port >= local_port && is_local_gw;
    bpf_log("Processing %dB msg from [%pI4:%u->%pI4:%u] (downstream: %d, retry: %d)", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream, is_retry);

    struct pipeline_ctx *ctx = NULL;
    enum pr_action res = PR_PASS;

    if (is_retry) {
        // TODO: under a heavy load, the context could have gotten evicted from the wait list
        ctx = bpf_map_lookup_elem(&utrn_wait_list, &ikey);
        if (ctx == NULL) {
            bpf_err("ERROR: Failed to find cached context for retry");
            return SK_DROP;
        }
    }
    else {
        struct prange pranges[MAX_MATCHES] = { 0 };
        bool pmatches[MAX_MATCHES] = { 0 };

        if (_parse(msg, pranges, pmatches) < 0) {
            bpf_err("ERROR: Failed to parse message");
            return SK_PASS;
        }
        
        ctx = bpf_map_lookup_elem(&ctx_percpu, &percpu_key);
        if (ctx == NULL) {
            bpf_err("ERROR: Failed to init pipeline context");
            return SK_DROP;
        }
        _init_pipeline_ctx(msg, pranges, ctx);
        res = _pipeline(msg, ctx, &ikey);
    }

    struct sock_key *ekey = NULL;
    if (res == PR_PASS) {    
        res = select_sock(&ikey, ctx, &ekey);
    }

    if (res == PR_DROP) {
        bpf_log("PLUGIN: Drop msg");
        return SK_DROP;
    }

    if (res == PR_UTRN) {
        if (bpf_map_update_elem(&utrn_wait_list, &ikey, ctx, BPF_ANY) < 0) {
            bpf_err("ERROR: Failed to add uturn token to wait list");
        }
        else {
            bpf_log("Add uturn to wait list [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
        }
        return SK_PASS;
    }

    if (ekey != NULL) {
        if (bpf_msg_redirect_hash(msg, &sock_map, ekey, BPF_F_INGRESS) == SK_PASS) {
            bpf_log("Redirecting msg from [%pI4:%u->%pI4:%u] to socket [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey->local.ip4, ekey->local.port, &ekey->remote.ip4, ekey->remote.port);
            return SK_PASS;
        }
        else {
            bpf_err("ERROR: Failed to redirect msg");
            return SK_DROP;
        }
    }

    // Either we didn't find an approriate socket or the message wasn't authorized
    // In both cases we abort if it's a retry
    // if (is_retry) {
    //     bpf_err("ERROR: Failed to find socket for retry");
    //     return SK_DROP;
    // }

    // we have a match, apply the filter's actions
    // if (fid > 0) {
    //     fid &= MAX_MATCH_MASK;
    //     bpf_log("Apply filter %d (matches: %d, modifications: %d)", fid, filters[fid].num_patterns, filters[fid].num_modifications);
        
    //     __s16 off = 0;
    //     u8 i, j;
    //     bpf_for(i, 0, filters[fid].num_modifications) {
    //         __s16 mid = -1;
    //         u16 idx_min = 0xFFFF;

    //         // find the first detected range
    //         // this is necessary because modify needs to be called in linear order
    //         // the length is checked to make sure that the pattern was actually detected
    //         bpf_for(j, 0, filters[fid].num_modifications) {
    //             __s16 mid_j = filters[fid].mids[j] & MAX_MATCH_MASK;
    //             if (pranges[mid_j].idx < idx_min && pranges[mid_j].len > 0) {
    //                 idx_min = pranges[mid_j].idx;
    //                 mid = mid_j;
    //             }
    //         }

    //         // check if we have to modify anything
    //         if (mid == -1) {
    //             break;
    //         }

    //         mid &= MAX_MATCH_MASK;

    //         bpf_log("Apply modification %d (fid: %d)", mid, fid);

    //         pranges[mid].idx += off;

    //         __s16 diff = 0;
    //         if (_modify(msg, &pranges[mid], &mods[mid], &diff) < 0) {
    //             bpf_err("ERROR: Modifying message failed.");
    //             break;
    //         }

    //         off += diff;
    //         pranges[mid].idx = 0xFFFF;
    //     }
    // }

    return SK_PASS;
}

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    if (ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        struct sock_key skey = {
            .local = {
                .ip4 = ops->local_ip4,
                .port = ops->local_port
            },
            .remote = {
                .ip4 = ops->remote_ip4,
                .port = bpf_ntohl(ops->remote_port)
            }
        };

        struct opt_frwd_token *ft = bpf_map_lookup_elem(&sock_wait_list, &skey.remote);
        if (ft != NULL) {
            if (bpf_sock_hash_update(ops, &sock_map, &skey, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            bpf_log("Add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);

            // add the socket before the forwarding token to avoid a race condition
            if (ft->is_some) {
                if (bpf_map_update_elem(&frwd_map, &ft->inner, &skey, BPF_ANY) < 0) {
                    bpf_err("ERROR: Failed to set forwarding token");
                }
                else {
                    bpf_log("Set forwarding token [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                }
            }
        }
    }

    return SK_PASS;
}