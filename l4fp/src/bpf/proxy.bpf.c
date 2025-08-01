#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

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

struct addr_key {
    u32 ip4;
    u32 port;
};

struct sock_key {
    struct addr_key local;
    struct addr_key remote;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 32768);
    __type(key, struct sock_key);
    __type(value, int);
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct sock_key);
    __type(value, int);
} sock_map_contains SEC(".maps");

volatile const u32 ip4_start;
volatile const u32 ip4_end;
volatile const u32 gw;

static __always_inline struct sock_key _invert_sock_key(const struct sock_key *key) {
    struct sock_key inv = {
        .local = key->remote,
        .remote = key->local,
    };
    return inv;
}

SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    // socket identifier of the ingress connection
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

    bpf_log("Processing %dB msg from [%pI4:%u->%pI4:%u]", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);

    if (ikey.remote.ip4 == gw) return SK_PASS;
    struct sock_key ekey = _invert_sock_key(&ikey);

    if (bpf_map_lookup_elem(&sock_map_contains, &ekey) == NULL) return SK_PASS;

    if (bpf_msg_redirect_hash(msg, &sock_map, &ekey, BPF_F_INGRESS) == SK_DROP) {
        bpf_err("ERROR: Failed to accelerate msg from [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
    }
    else {
        bpf_log("Transport acceleration for [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
    }

    return SK_PASS;
}

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    if (ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        // we don't want to get called anymore for this connection
        bpf_sock_ops_cb_flags_set(ops, 0);

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

        bpf_log("Established socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);

        bool local_in_network = bpf_ntohl(skey.local.ip4) >= bpf_ntohl(ip4_start) && bpf_ntohl(skey.local.ip4) <= bpf_ntohl(ip4_end);
        bool remote_in_network = bpf_ntohl(skey.remote.ip4) >= bpf_ntohl(ip4_start) && bpf_ntohl(skey.remote.ip4) <= bpf_ntohl(ip4_end);
        bool in_network = local_in_network && remote_in_network;

        if (in_network) {
            if (bpf_sock_hash_update(ops, &sock_map, &skey, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            int flag = 1;
            bpf_map_update_elem(&sock_map_contains, &skey, &flag, BPF_ANY);

            bpf_log("Add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
        }
    }

    return SK_PASS;
}
