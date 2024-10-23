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
#define MAX_BYTES 0xFFFE
#define MAX_MATCHES 16
#define MAX_MATCH_MASK 15
#define MAX_MOD_LEN 0xFF

enum pr_action {
	PR_DROP = 0,
	PR_PASS,
    PR_USPA
};

struct addr_key {
    __u32 ip4;
    __u32 port;
};

struct sock_key {
    struct addr_key local;
    struct addr_key remote;
};

struct wait_list_key {
    __u32 ip4;
    __u32 port;
};

struct wait_list_val {
    __u32 sock_key; 

    __u32 num_routes;
    __u32 route_fid[MAX_MATCHES]; // this could be u8, but that makes it difficult to manage from userspace
    __u32 route_sock_key[MAX_MATCHES];
};

struct req_route_key {
    __u32 local_ip4;
    __u32 local_port;
    __u32 remote_ip4;
    __u32 remote_port;
    __u32 fid; 
};

struct res_route_key {
    __u32 local_ip4;
    __u32 local_port;
    __u32 remote_ip4;
    __u32 remote_port;
};

struct res_route_val {
    __u32 sock_key;
    __u32 fid;
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
    __type(key, struct req_route_key);
    __type(value, __u32);
} req_route_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct res_route_key);
    __type(value, struct res_route_val);
} res_route_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, int);
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct wait_list_key);
    __type(value, struct wait_list_val);
} sock_wait_list SEC(".maps");

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
volatile const __u32 s2ts[128][256] = { s_init };
volatile const struct modification mods[MAX_MATCHES] = { 0 };

struct prange pranges[MAX_MATCHES] = { 0 };
bool pmatches[MAX_MATCHES] = { 0 };

// ----------------------------------------------

struct ds_conn_state {
    __u32 num_bytes;
    __u32 num_reqs;
    __u64 last_req_ts;
    __u64 this_req_ts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct sock_key);
    __type(value, struct ds_conn_state);
} ds_conns SEC(".maps");

struct parse_res {
    __u32 content_length;
    bool backend_is_server1;
    bool backend_is_server2;
};

int update_ds_state(struct sock_key *dkey, struct parse_res *params) {
    bpf_log("Update DS state: server1: %d, server2: %d, content-length: %d", params->backend_is_server1, params->backend_is_server2, params->content_length);
    struct ds_conn_state *state = bpf_map_lookup_elem(&ds_conns, dkey);
    if (state == NULL) {
        struct ds_conn_state new_state = {
            .num_bytes = params->content_length,
            .num_reqs = 1,
            .last_req_ts = 0,
            .this_req_ts = bpf_ktime_get_ns()
        };
        bpf_map_update_elem(&ds_conns, dkey, &new_state, BPF_ANY);
    }
    else {
        state->num_bytes += params->content_length;
        state->num_reqs++;
        state->last_req_ts = state->this_req_ts;
        state->this_req_ts = bpf_ktime_get_ns();
    }

    return 0;
}

// ----------------------------------------------

static __always_inline void _next(__u16 state, __u32 input, __u16 *next_state, __u16 *action) {
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

__u32 cidx[MAX_MATCHES] = { 0 };
static __always_inline int _parse(const struct sk_msg_md *msg) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    __u32 len = (data_end - data) & MAX_BYTES;

    if (len == 0) {
        return 0;
    }
    
    __u16 s = s_init;
    __u8 num_mods = 0;

    __builtin_memset(cidx, 0, sizeof(cidx));
    __builtin_memset(pranges, 0, sizeof(pranges));
    __builtin_memset(pmatches, 0, sizeof(pmatches));

    __u32 i;
    bpf_for(i, 0, len) {
        if (data + i + 1 > data_end) return -1;
        char c = data[i];

        __u16 a = 0;
        __u16 s_old = s;
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
            bpf_log("Match %d at %d", mid, i);
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

static __always_inline void _init_parse_res(struct sk_msg_md *msg, struct parse_res *res) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    __u32 len = (data_end - data) & MAX_BYTES;

    const struct prange r0 = pranges[0];
    unsigned long val = 0;

    bpf_strtoul(data + r0.idx, r0.len, 10, &val);

    res->backend_is_server1 = pmatches[0];
    res->backend_is_server2 = pmatches[1];
    res->content_length = (__u32)val;
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

static __always_inline int _try_redirect_req(struct sk_msg_md *msg, __u8 fid) {
    struct req_route_key rkey = { 
        .local_ip4 = msg->local_ip4,
        .local_port = msg->local_port,
        .remote_ip4 = msg->remote_ip4,
        .remote_port = bpf_ntohl(msg->remote_port),
        .fid = fid
    };

    __u32 *skey = bpf_map_lookup_elem(&req_route_map, &rkey);
    if (skey == NULL) {
        bpf_err("ERROR: No req route found for [%pI4:%u->%pI4:%u|%u]", &rkey.local_ip4, rkey.local_port, &rkey.remote_ip4, rkey.remote_port, rkey.fid);
        return SK_PASS;
    }

    int r = bpf_msg_redirect_hash(msg, &sock_map, skey, BPF_F_INGRESS);
    if (r == SK_DROP) {
        bpf_err("ERROR: Redirect failed");
    }
    else {
        bpf_log("Redirecting req [%pI4:%u->%pI4:%u|%u] to socket %d", &rkey.local_ip4, rkey.local_port, &rkey.remote_ip4, rkey.remote_port, rkey.fid, *skey);
    }

    return r;
}

static __always_inline int _try_redirect_res(struct sk_msg_md *msg, __u8 *fid) {
    struct res_route_key rkey = { 
        .local_ip4 = msg->local_ip4,
        .local_port = msg->local_port,
        .remote_ip4 = msg->remote_ip4,
        .remote_port = bpf_ntohl(msg->remote_port),
    };

    struct res_route_val *rval = bpf_map_lookup_elem(&res_route_map, &rkey);
    if (rval == NULL) {
        bpf_err("ERROR: No res route found for [%pI4:%u->%pI4:%u]", &rkey.local_ip4, rkey.local_port, &rkey.remote_ip4, rkey.remote_port);
        return SK_PASS;
    }

    int r = bpf_msg_redirect_hash(msg, &sock_map, &rval->sock_key, BPF_F_INGRESS);
    if (r == SK_DROP) {
        bpf_err("ERROR: Redirect failed");
    }
    else {
        *fid = rval->fid;
        bpf_log("Redirecting res [%pI4:%u->%pI4:%u|%u] to socket %d", &rkey.local_ip4, rkey.local_port, &rkey.remote_ip4, rkey.remote_port, rval->fid, rval->sock_key);
    }

    return r;
}

SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    __u8 fid = 0;
    int r = SK_PASS;
    bool downstream = msg->remote_ip4 == ip4 && bpf_ntohl(msg->remote_port) == port;
    bpf_log("Processing %dB msg (downstream: %d)", msg->size, downstream);

    if (_parse(msg) < 0) return r;

    struct parse_res params;
    _init_parse_res(msg, &params);

    struct sock_key skey = {
        .local = {
            .ip4 = msg->local_ip4,
            .port = msg->local_port
        },
        .remote = {
            .ip4 = msg->remote_ip4,
            .port = bpf_ntohl(msg->remote_port)
        }
    };

    // parsing was successful, check if we have a match
    // we only do this for requests
    // for responses, we get the fid to apply from the route
    if (downstream) {
        update_ds_state(&skey, &params);
        r = _try_redirect_req(msg, fid);
    }
    else {
        r = _try_redirect_res(msg, &fid);
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

    return r;
}

static __always_inline int _add_routes(struct bpf_sock_ops *ops, struct wait_list_val *wval) {
    for (int i = 0; i < MAX_MATCHES; i++) {
        if (i == wval->num_routes) break;

        // if it's downstream, add the route to req_route_map, otherwise to res_route_map
        bool downstream = ops->remote_ip4 == ip4 && bpf_ntohl(ops->remote_port) == port;
        if (downstream) {
            struct req_route_key rkey = {
                .local_ip4 = ops->local_ip4,
                .local_port = ops->local_port,
                .remote_ip4 = ops->remote_ip4,
                .remote_port = bpf_ntohl(ops->remote_port),
                .fid = wval->route_fid[i]
            };

            if (bpf_map_update_elem(&req_route_map, &rkey, &wval->route_sock_key[i], BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to add req route [%pI4:%u->%pI4:%u|%u] to socket %d", &rkey.local_ip4, rkey.local_port, &rkey.remote_ip4, rkey.remote_port, rkey.fid, wval->route_sock_key[i]);
                return -1;
            }

            bpf_log("Add req route [%pI4:%u->%pI4:%u|%u] to socket %d", &rkey.local_ip4, rkey.local_port, &rkey.remote_ip4, rkey.remote_port, rkey.fid, wval->route_sock_key[i]);
        }
        else {
            struct res_route_key rkey = {
                .local_ip4 = ops->local_ip4,
                .local_port = ops->local_port,
                .remote_ip4 = ops->remote_ip4,
                .remote_port = bpf_ntohl(ops->remote_port),
            };

            struct res_route_val rval = {
                .sock_key = wval->route_sock_key[i],
                .fid = wval->route_fid[i]
            };

            if (bpf_map_update_elem(&res_route_map, &rkey, &rval, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to add res route [%pI4:%u->%pI4:%u|%u] to socket %d", &rkey.local_ip4, rkey.local_port, &rkey.remote_ip4, rkey.remote_port, rval.fid, wval->route_sock_key[i]);
                return -1;
            }

            bpf_log("Add res route [%pI4:%u->%pI4:%u|%u] to socket %d", &rkey.local_ip4, rkey.local_port, &rkey.remote_ip4, rkey.remote_port, rval.fid, wval->route_sock_key[i]);
        }
    }

    return 0;
}

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    // check if this socket is either side of a route that waits for its sockets
    if (ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        __u32 local_ip4 = ops->local_ip4;
        __u32 local_port = ops->local_port;
        __u32 remote_ip4 = ops->remote_ip4;
        __u32 remote_port = bpf_ntohl(ops->remote_port);

        struct wait_list_key wkey = { 
            .ip4 = remote_ip4,
            .port = remote_port
        };
        struct wait_list_val *val = bpf_map_lookup_elem(&sock_wait_list, &wkey);

        if (val != NULL) {
            _add_routes(ops, val);

            if (bpf_sock_hash_update(ops, &sock_map, &val->sock_key, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to add socket [%pI4:%u->%pI4:%u]", &local_ip4, local_port, &remote_ip4, remote_port);
                return SK_PASS;
            }

            bpf_log("Add socket [%pI4:%u->%pI4:%u] with key %d", &local_ip4, local_port, &remote_ip4, remote_port, val->sock_key);
            bpf_map_delete_elem(&sock_wait_list, &wkey);
        }
    }

    return SK_PASS;
}