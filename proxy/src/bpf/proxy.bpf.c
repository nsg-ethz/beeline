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
    __type(value, __u32);
} forward_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 8192);
    __type(key, __u32);
    __type(value, int);
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct addr_key);
    __type(value, u32);
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
const __u32 local_port = 12345;
volatile const __u32 s2ts[128][256] = { s_init };
volatile const struct modification mods[MAX_MATCHES] = { 0 };

struct prange pranges[MAX_MATCHES] = { 0 };
bool pmatches[MAX_MATCHES] = { 0 };

// ----------------------------------------------
// compiler generated

struct parse_res {
    char backend[4096];
    __u32 backend_len;
    __u32 content_length;
} pres;

enum fd_direction {
    PR_DOWNSTREAM = 1,
    PR_UPSTREAM
};

enum fd_backend {
    PR_SERVER1 = 1,
    PR_SERVER2
};

struct forwarding_decision {
    __u8 direction;
    __u8 backend;
    __u8 num_bytes_min;
    struct sock_key origin;
};

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
    bpf_log("Update DS state: server: %s, content-length: %d", res->backend, res->content_length);
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
    __u64 req_interval = state->this_req_ts - state->last_req_ts;
    bpf_log("Request interval: %llu", req_interval);
    if (req_interval < 10000000) {
        return SK_DROP;
    }

    const char *server1 = "server1";
    bool backend_is_server1 = bpf_strncmp(res->backend, 7, server1) == 0;
    const char *server2 = "server2";
    bool backend_is_server2 = bpf_strncmp(res->backend, 7, server2) == 0;
    if (!backend_is_server1 && !backend_is_server2) {
        return SK_DROP;
    }

    fd->direction = PR_UPSTREAM;
    fd->backend = backend_is_server1 ? PR_SERVER1 : PR_SERVER2;
    fd->num_bytes_min = true;
    
    return SK_PASS;
}

int forward_us_conn(const struct sock_key *ukey, const struct us_conn_state *state, const struct parse_res *res, struct forwarding_decision *fd) {
    fd->direction = PR_DOWNSTREAM;
    fd->origin = *ukey;

    return SK_PASS;
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

char buf[0xfff];
static __always_inline int _init_parse_res(struct sk_msg_md *msg) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;

    struct prange r0 = pranges[0];
    __u32 r0_len = r0.len & 0xfff;
    if (r0_len == 0) return -1;
    if (bpf_probe_read_kernel(pres.backend, r0_len, data + r0.idx) < 0) return -1;
    pres.backend_len = r0_len;

    struct prange r1 = pranges[1];
    __u32 r1_len = r1.len & 0xfff;
    if (r1_len == 0) return -1;
    if (bpf_probe_read_kernel(buf, r1_len, data + r1.idx) < 0) return -1;
    unsigned long val = 0;
    bpf_strtoul(buf, r1_len, 10, &val);
    pres.content_length = (__u32)val;

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

    __u8 fid = 0;
    enum sk_action act = SK_PASS;
    bool downstream = (ikey.remote.ip4 == ip4 && ikey.remote.port == port);
    bool retry = (ikey.local.ip4 == ip4 && ikey.local.port != port) && !downstream && ikey.local.port >= local_port;
    bpf_log("Processing %dB msg from [%pI4:%u->%pI4:%u]", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);

    struct forwarding_decision fd = { 0 };
    if (retry) {
        struct forwarding_decision *fd_cached = bpf_map_lookup_elem(&forward_wait_list, &ikey);
        if (fd_cached == NULL) {
            bpf_err("ERROR: Failed to find forwarding decision for retry");
            return SK_DROP;
        }

        fd = *fd_cached;
    }
    else {
        if (_parse(msg) < 0) return act;
        _init_parse_res(msg);

        if (downstream) {
            struct ds_conn_state state = { 0 };
            if (update_ds_state(&ikey, &pres, &state) < 0) {
                bpf_err("ERROR: Updating downstream connection state failed.");
            }
            
            act = forward_ds_conn(&ikey, &state, &pres, &fd);
        }
        else {
            struct us_conn_state state = { 0 };
            if (update_us_state(&ikey, &pres, &state) < 0) {
                bpf_err("ERROR: Updating upstream connection state failed.");
            }

            act = forward_us_conn(&ikey, &state, &pres, &fd);
        }
        if (act == SK_DROP) {
            bpf_log("Plugin decided to drop msg");
            return act;
        }
    }

    __u32 *ekey = bpf_map_lookup_elem(&forward_map, &fd);
    if (ekey == NULL) {
        if (retry) {
            bpf_err("ERROR: Failed to find socket for retry");
            return SK_DROP;
        }
        
        bpf_log("Add forwarding decision to wait list [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
        if (bpf_map_update_elem(&forward_wait_list, &ikey, &fd, BPF_ANY) < 0) {
            bpf_err("ERROR: Failed to add forwarding decision to wait list");
        }
        return SK_PASS;
    }

    act = bpf_msg_redirect_hash(msg, &sock_map, ekey, BPF_F_INGRESS);
    if (act == SK_DROP) {
        bpf_err("ERROR: Redirect failed");
        return act;
    }
    
    bpf_log("Redirecting msg from [%pI4:%u->%pI4:%u] to socket %d", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, *ekey);

    // at this point we have to manage special forwarding decision
    if (downstream && fd.direction == PR_UPSTREAM) {
        struct forwarding_decision fd_org = { 0 };
        fd_org.direction = PR_DOWNSTREAM;
        fd_org.origin = ikey;

        if (bpf_map_update_elem(&forward_map, &fd_org, ekey, BPF_ANY) < 0) {
            bpf_err("ERROR: Failed to add origin forwarding decision");
        }
        else {
            bpf_log("Add origin forwarding decision [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
        }
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

    return act;
}

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    // check if this socket is either side of a route that waits for its sockets
    if (ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        __u32 local_ip = ops->local_ip4;
        __u32 local_port = ops->local_port;
        struct addr_key akey = {
            .ip4 = ops->remote_ip4,
            .port = bpf_ntohl(ops->remote_port)
        };

        __u32 *sock_id = bpf_map_lookup_elem(&sock_wait_list, &akey);
        if (sock_id != NULL) {
            if (bpf_sock_hash_update(ops, &sock_map, sock_id, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to add socket [%pI4:%u->%pI4:%u]", &local_ip, local_port, &akey.ip4, akey.port);
                return SK_PASS;
            }

            bpf_log("Add socket [%pI4:%u->%pI4:%u]", &local_ip, local_port, &akey.ip4, akey.port);
        }
    }

    return SK_PASS;
}