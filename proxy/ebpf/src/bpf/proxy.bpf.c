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
    __u8 num_patterns;
    __u8 num_modifications;
    __u8 mids[MAX_MATCHES];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __uint(key_size, sizeof(struct req_route_key));
    __uint(value_size, sizeof(__u32));
} req_route_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __uint(key_size, sizeof(struct res_route_key));
    __uint(value_size, sizeof(struct res_route_val));
} res_route_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 8192);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __uint(key_size, sizeof(struct wait_list_key));
    __uint(value_size, sizeof(struct wait_list_val));
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
volatile const struct filter filters[MAX_MATCHES] = { 0 };

struct capture_group cgs[MAX_MATCHES] = { 0 };
// this is internal to the _parse function
__u32 mod_idx[MAX_MATCHES] = { 0 };
__u32 fid_cnt[MAX_MATCHES] = { 0 };

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

static __always_inline int _parse(const struct sk_msg_md *msg) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    __u32 len = (data_end - data) & MAX_BYTES;

    if (len == 0) {
        return 0;
    }
    
    __u16 s = s_init;
    __u8 num_mods = 0;

    memset(cgs, 0, sizeof(cgs));
    memset(mod_idx, 0, sizeof(mod_idx));
    memset(fid_cnt, 0, sizeof(fid_cnt));

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
            mod_idx[cid] = i;
        }
        if ((a & a_end_capture) != 0) {
            __u16 cid = ((a & a_id_1_mask) >> 6) & MAX_MATCH_MASK;
            __u16 mid = a & a_id_2_mask & MAX_MATCH_MASK;
            bpf_log("End capture range (%d, %d) in [%d, %d]", cid, mid, mod_idx[cid], i - mod_idx[cid] + 1);

            cgs[mid] = (struct capture_group) {
                .id = mid,
                .idx = mod_idx[cid],
                .len = i - mod_idx[cid] + 1
            };
            mod_idx[cid] = 0;
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

    bool downstream = msg->remote_ip4 == ip4 && bpf_ntohl(msg->remote_port) == port;
    bpf_log("Processing %dB msg (downstream: %d)", msg->size, downstream);
    int r = SK_PASS;

    if (_parse(msg) == 0) {
        // parsing was successful, check if we have a match
        // we only do this for requests
        // for responses, we get the fid to apply from the route
        if (downstream) {
            __u8 i;
            bpf_for(i, 1, MAX_MATCHES) {
                i &= MAX_MATCH_MASK;
                if (fid_cnt[i] == filters[i].num_patterns && filters[i].num_patterns > 0) {
                    fid = i;
                    break;
                } 
            }

            r = _try_redirect_req(msg, fid);
        }
        else {
            r = _try_redirect_res(msg, &fid);
        }

        // we have a match, apply the filter's actions
        if (fid > 0) {
            fid &= MAX_MATCH_MASK;
            bpf_log("Apply filter %d (matches: %d, modifications: %d)", fid, filters[fid].num_patterns, filters[fid].num_modifications);
            
            __s16 off = 0;
            __u8 i, j;
            bpf_for(i, 0, filters[fid].num_modifications) {
                __s16 mid = -1;
                __u16 idx_min = 0xFFFF;

                // find the first detected range
                // this is necessary because modify needs to be called in linear order
                // the length is checked to make sure that the pattern was actually detected
                bpf_for(j, 0, filters[fid].num_modifications) {
                    __s16 mid_j = filters[fid].mids[j] & MAX_MATCH_MASK;
                    if (cgs[mid_j].idx < idx_min && cgs[mid_j].len > 0) {
                        idx_min = cgs[mid_j].idx;
                        mid = mid_j;
                    }
                }

                // check if we have to modify anything
                if (mid == -1) {
                    break;
                }

                mid &= MAX_MATCH_MASK;

                bpf_log("Apply modification %d (fid: %d)", mid, fid);

                cgs[mid].idx += off;

                __s16 diff = 0;
                if (_modify(msg, &cgs[mid], &diff) < 0) {
                    bpf_err("ERROR: Modifying message failed.");
                    break;
                }

                off += diff;
                cgs[mid].idx = 0xFFFF;
            }
        }
    }

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

            bpf_log("Add req route [%pI4:%u->%pI4:%u|%u] to socket %d", &rkey.local_ip4, rkey.local_port, &rkey.remote_ip4, rkey.remote_port, rval.fid, wval->route_sock_key[i]);
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
