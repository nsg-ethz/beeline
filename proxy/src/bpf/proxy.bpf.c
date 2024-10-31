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
    __u32 ip4;
    __u32 port;
};

struct sock_key {
    struct addr_key local;
    struct addr_key remote;
};

struct prange {
    __u16 idx;
    __u16 len;
};

struct modification {
    __u8 len;
    char str[MAX_MOD_LEN];
    __u8 tail;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct sock_key);
    __type(value, struct forwarding_decision);
} forward_wait_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct forwarding_decision);
    __type(value, struct sock_key);
} forward_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 8192);
    __type(key, struct sock_key);
    __type(value, int);
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct addr_key);
    __type(value, struct opt_forwarding_decision);
} sock_wait_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct parse_res);
} pres_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct sock_key);
    __type(value, struct ds_conn_state);
} ds_conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct addr_key);
    __type(value, struct us_conn_state);
} us_conns SEC(".maps");

const __u32 a_mask = 0xFFFF0000;
const __u16 a_match = 1 << 15;
const __u16 a_done = 1 << 14;
const __u16 a_start_capture = 1 << 13;
const __u16 a_end_capture = 1 << 12;
// if a_match -> then this represents the fid
// if a_done -> then this is 0
// if a_start_capture -> then this is the cid
// if a_end_capture -> then this is cid | mid
const __u16 a_id_mask = 0x0FFF;
const __u16 a_id_1_mask = 0x0FC0;
const __u16 a_id_2_mask = 0x003F;

const __u32 s_mask = 0x0000FFFF;
const __u16 s_init = 0;
const __u16 s_any = 1;

volatile const __u32 ip4;
volatile const __u32 port;
const __u32 local_port = 12345;
const __u32 local_gw = 254;
volatile const __u32 s2ts[128][256];
volatile const struct modification mods[MAX_MATCHES] = { 0 };

// ----------------------------------------------
// compiler generated

struct parse_res {
    char backend[4096];
    __u32 backend_len;
    __u32 content_length;
    __u32 conn_id;
};

enum fd_direction {
    PR_DOWNSTREAM = 1,
    PR_UPSTREAM
};

enum fd_backend {
    PR_SERVER1 = 1,
    PR_SERVER2 = 2,
    PR_SERVER3 = 3,
    PR_SERVER4 = 4
};

// TODO: this needs special care to get aligned
struct forwarding_decision {
    __u32 conn_id;
    __u8 direction;
    __u8 backend;
    __u8 num_bytes_min;
};

struct opt_forwarding_decision {
    __u8 is_some;
    struct forwarding_decision inner;
};

static __always_inline void _init_parse_res(struct sk_msg_md *msg, const struct prange *pranges, struct parse_res *pres) {
    char *data = (char *)(long)msg->data;
    char buf[64]; // a number cannot be larger than 64 bytes

    struct prange r0 = pranges[0];
    __u32 r0_len = r0.len & 63;
    if (r0_len > 0 && bpf_probe_read_kernel(pres->backend, r0_len, data + r0.idx) == 0) {
        pres->backend_len = r0_len;
    }
    else {
        pres->backend_len = 0;
    }

    struct prange r1 = pranges[1];
    __u32 r1_len = r1.len & 63;
    if (r1_len > 0 && bpf_probe_read_kernel(buf, r1_len, data + r1.idx) == 0) {
        unsigned long val = 0;
        bpf_strtoul(buf, r1_len, 10, &val);
        pres->content_length = val;
    }
    else {
        pres->content_length = 0;
    }

    struct prange r2 = pranges[2];
    __u32 r2_len = r2.len & 63;
    if (r2_len > 0 && bpf_probe_read_kernel(buf, r2_len, data + r2.idx) == 0) {
        unsigned long val = 0;
        bpf_strtoul(buf, r2_len, 10, &val);
        pres->conn_id = val;
    }
    else {
        pres->conn_id = 0;
    }
}

// ----------------------------------------------
// user provided

struct ds_conn_state {
    __u32 num_bytes;
    __u32 num_reqs;
    __u64 last_req_ts;
    __u64 this_req_ts;
};

struct us_conn_state {
    __u32 num_bytes;
    __u32 num_reqs;
};

int update_ds_state(const struct sock_key *dkey, const struct parse_res *res, struct ds_conn_state *state) {
    struct ds_conn_state *s = bpf_map_lookup_elem(&ds_conns, dkey);
    if (s == NULL) {
        *state = (struct ds_conn_state) {
            .num_bytes = res->content_length,
            .num_reqs = 1,
            .last_req_ts = 0,
            .this_req_ts = bpf_ktime_get_ns()
        };
        bpf_map_update_elem(&ds_conns, dkey, state, BPF_ANY);
    }
    else {
        s->num_bytes += res->content_length;
        s->num_reqs++;
        s->last_req_ts = s->this_req_ts;
        s->this_req_ts = bpf_ktime_get_ns();
        state = s;
    }

    return 0;
}

int update_us_state(const struct sock_key *ukey, const struct parse_res *res, struct us_conn_state *state) {
    const struct addr_key *rukey = &ukey->remote;
    struct us_conn_state *s = bpf_map_lookup_elem(&us_conns, rukey);
    if (s == NULL) {
        *state = (struct us_conn_state) {
            .num_bytes = res->content_length,
            .num_reqs = 1,
        };
        bpf_map_update_elem(&us_conns, rukey, state, BPF_ANY);
    }
    else {
        s->num_bytes += res->content_length;
        s->num_reqs++;
        state = s;
    }

    return 0;
}

int forward_ds_conn(const struct sock_key *dkey, const struct ds_conn_state *state, const struct parse_res *res, struct forwarding_decision *fd) {
    if (dkey == NULL || state == NULL || res == NULL || fd == NULL) {
        return SK_DROP;
    }

    // rate limit connection if it's sent a request less than 1ms ago
    // __u64 req_interval = state->this_req_ts - state->last_req_ts;
    // if (req_interval < 10000000) {
    //     return SK_DROP;
    // }

    const char *server1 = "server1";
    bool backend_is_server1 = bpf_strncmp(res->backend, 7, server1) == 0;
    const char *server2 = "server2";
    bool backend_is_server2 = bpf_strncmp(res->backend, 7, server2) == 0;
    const char *server3 = "server3";
    bool backend_is_server3 = bpf_strncmp(res->backend, 7, server3) == 0;
    const char *server4 = "server4";
    bool backend_is_server4 = bpf_strncmp(res->backend, 7, server4) == 0;

    if (!backend_is_server1 && !backend_is_server2 && !backend_is_server3 && !backend_is_server4) {
        return SK_DROP;
    }

    if (backend_is_server1) fd->backend = PR_SERVER1;
    if (backend_is_server2) fd->backend = PR_SERVER2;
    if (backend_is_server3) fd->backend = PR_SERVER3;
    if (backend_is_server4) fd->backend = PR_SERVER4;

    fd->direction = PR_UPSTREAM;
    fd->num_bytes_min = true;
    
    return SK_PASS;
}

int set_ds_forwarding_decision(const struct sock_key *dkey, const struct ds_conn_state *state, const struct parse_res *res, struct forwarding_decision *fd) {
    fd->direction = PR_DOWNSTREAM;
    fd->conn_id = res->conn_id;

    return SK_PASS;
}

int forward_us_conn(const struct sock_key *ukey, const struct us_conn_state *state, const struct parse_res *res, struct forwarding_decision *fd) {
    fd->direction = PR_DOWNSTREAM;
    fd->conn_id = res->conn_id;

    return SK_PASS;
}

// ----------------------------------------------

static __always_inline void _next(__u16 state, __u32 input, __u16 *next_state, __u16 *action) {
    state &= 0x7F;
    input &= 0xFF;

    __u32 sa = s2ts[state][input];
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

static __always_inline int _parse(const struct sk_msg_md *msg, struct prange *pranges, bool *pmatches) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    __u32 len = (data_end - data) & MAX_BYTES;

    if (len == 0) {
        return 0;
    }

    __u32 cidx[MAX_MATCHES] = { 0 };

    __u16 s = s_init;
    __u32 i;
    bpf_for(i, 0, len) {
        if (data + i + 1 > data_end) return -1;
        char c = data[i];

        __u16 a = 0;
        _next(s, c, &s, &a);

        // it should never happen that any of these cases are true simultaneously
        // but it makes the verifier happy when we don't use else if here
        if ((a & a_start_capture) != 0) {
            __u16 cid = a & a_id_mask & MAX_MATCH_MASK;
            bpf_log("Start capture range (%d, ?) in [%d, ...]", cid, i);
            cidx[cid] = i;
        }
        if ((a & a_end_capture) != 0) {
            __u16 cid = ((a & a_id_1_mask) >> 6) & MAX_MATCH_MASK;
            __u16 rid = a & a_id_2_mask & MAX_MATCH_MASK;
            bpf_log("End capture range (%d, %d) in [%d, %d]", cid, rid, cidx[cid], i - cidx[cid] + 1);

            pranges[rid] = (struct prange) {
                .idx = cidx[cid],
                .len = i - cidx[cid] + 1
            };
            cidx[cid] = 0;
        }
        if ((a & a_match) != 0) {
            __u16 mid = a & a_id_mask & MAX_MATCH_MASK;
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

    return 0;
}

static __always_inline int _modify(struct sk_msg_md *msg, const struct prange *r, volatile const struct modification *m, __s16 *diff) {
    // in case something fails, we don't want to resport a wrong diff
    if (diff == NULL) return -1;
    *diff = 0;

    __u16 len = r->len;
    __u16 idx = r->idx;

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
    
    __u16 i;
    bpf_for(i, 0, m->len) {
        if (data + i + 1 > data_end) return -1;
        data[i] = m->str[i];
    }

    return 0;
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

    struct forwarding_decision fd = { 0 };
    if (is_retry) {
        struct forwarding_decision *fd_cached = bpf_map_lookup_elem(&forward_wait_list, &ikey);
        if (fd_cached == NULL) {
            bpf_err("ERROR: Failed to find forwarding decision for retry");
            return SK_DROP;
        }

        fd = *fd_cached;
    }
    else {
        struct prange pranges[MAX_MATCHES] = { 0 };
        bool pmatches[MAX_MATCHES] = { 0 };

        if (_parse(msg, pranges, pmatches) < 0) return SK_DROP;
        
        __u32 pres_key = 0;
        struct parse_res *pres = bpf_map_lookup_elem(&pres_map, &pres_key);
        if (pres == NULL) {
            bpf_err("ERROR: Failed to init parse result");
            return SK_DROP;
        }
        _init_parse_res(msg, pranges, pres);

        if (is_downstream) {
            struct ds_conn_state state = { 0 };
            if (update_ds_state(&ikey, pres, &state) < 0) {
                bpf_err("ERROR: Updating downstream connection state failed.");
            }
            
            if (forward_ds_conn(&ikey, &state, pres, &fd) == SK_DROP) {
                bpf_log("Plugin decided to drop downstream msg");
                return SK_DROP;
            }

            // at this point we have to ask the plugin how it wants to route
            // this request back to the client
            struct forwarding_decision fd_inv = { 0 };
            if (set_ds_forwarding_decision(&ikey, &state, pres, &fd_inv) == SK_DROP) {
                bpf_log("Did not find inverse forwarding decision. Dropping.");
                return SK_DROP;
            }

            if (bpf_map_update_elem(&forward_map, &fd_inv, &ikey, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to set downstream forwarding decision");
            }
            else {
                bpf_log("Set downstream forwarding decision [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
            }
        }
        else {
            struct us_conn_state state = { 0 };
            if (update_us_state(&ikey, pres, &state) < 0) {
                bpf_err("ERROR: Updating upstream connection state failed.");
            }

            if (forward_us_conn(&ikey, &state, pres, &fd) == SK_DROP) {
                bpf_log("Plugin decided to drop upstream msg");
                return SK_DROP;
            }
        }
    }

    struct sock_key *ekey = bpf_map_lookup_elem(&forward_map, &fd);
    bool redirected = false;

    if (ekey != NULL) {
        if (bpf_msg_redirect_hash(msg, &sock_map, ekey, BPF_F_INGRESS) == SK_DROP) {
            bpf_log("WARN: Redirection from [%pI4:%u->%pI4:%u] to socket [%pI4:%u->%pI4:%u] failed", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey->local.ip4, ekey->local.port, &ekey->remote.ip4, ekey->remote.port);
        }
        else {
            bpf_log("Redirecting msg from [%pI4:%u->%pI4:%u] to socket [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey->local.ip4, ekey->local.port, &ekey->remote.ip4, ekey->remote.port);
            redirected = true;
        }
    }

    if (!redirected) {
        if (is_retry) {
            bpf_err("ERROR: Failed to find socket for retry");
            return SK_DROP;
        }
        
        bpf_log("Add forwarding decision to wait list [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
        if (bpf_map_update_elem(&forward_wait_list, &ikey, &fd, BPF_ANY) < 0) {
            bpf_err("ERROR: Failed to add forwarding decision to wait list");
        }
        return SK_PASS;
    }


    // we have a match, apply the filter's actions
    // if (fid > 0) {
    //     fid &= MAX_MATCH_MASK;
    //     bpf_log("Apply filter %d (matches: %d, modifications: %d)", fid, filters[fid].num_patterns, filters[fid].num_modifications);
        
    //     __s16 off = 0;
    //     __u8 i, j;
    //     bpf_for(i, 0, filters[fid].num_modifications) {
    //         __s16 mid = -1;
    //         __u16 idx_min = 0xFFFF;

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

        struct opt_forwarding_decision *fd = bpf_map_lookup_elem(&sock_wait_list, &skey.remote);
        if (fd != NULL) {
            if (bpf_sock_hash_update(ops, &sock_map, &skey, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            bpf_log("Add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);

            // add the socket before the forwarding decision to avoid a race condition
            if (fd->is_some) {
                if (bpf_map_update_elem(&forward_map, &fd->inner, &skey, BPF_ANY) < 0) {
                    bpf_err("ERROR: Failed to set forwarding decision");
                }
                else {
                    bpf_log("Set forwarding decision [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                }
            }
        }
    }

    return SK_PASS;
}