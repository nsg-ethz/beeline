#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

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
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, int);
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32768);
    __type(key, struct sock_key);
    __type(value, struct sock_key);
} ekey_map SEC(".maps");

volatile const u32 ip4;

static __always_inline struct sock_key _invert_sock_key(const struct sock_key *key) {
    struct sock_key inv = {
        .local = key->remote,
        .remote = key->local,
    };
    return inv;
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

    bpf_log("Processing %dB msg from [%pI4:%u->%pI4:%u]", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);

    // struct sock_key ekey = _invert_sock_key(&ikey);
    // int *cnt = bpf_map_lookup_elem(&req_count, &ekey);

    // if (cnt == NULL || *cnt <= 10) {
    //     int new_cnt = (cnt == NULL) ? 1 : *cnt + 1;
    //     bpf_map_update_elem(&req_count, &ekey, &new_cnt, BPF_ANY);
    //     return SK_PASS;
    // }

    struct sock_key *ekey = bpf_map_lookup_elem(&ekey_map, &ikey);
    if (!ekey) {
        struct sock_key new_ekey = _invert_sock_key(&ikey);
        if (bpf_map_update_elem(&ekey_map, &ikey, &new_ekey, BPF_ANY) < 0) {
            bpf_err("Failed to update ekey_map");
        }
        return SK_PASS;
    }
    else {
        if (bpf_msg_redirect_hash(msg, &sock_map, &ekey, BPF_F_INGRESS) == SK_DROP) {
            // It's possible that this fails because we haven't added the egress socket to the sockmap yet
            // In this case we will have to traverse the network stack
            bpf_log("WARN: Failed to redirect msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port);
        }
        else {
            bpf_log("Redirecting msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port);
        }
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

        if (skey.remote.ip4 == ip4 || skey.local.ip4 == ip4) {
            if (bpf_sock_hash_update(ops, &sock_map, &skey, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            bpf_log("Add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
        }
    }

    return SK_PASS;
}
