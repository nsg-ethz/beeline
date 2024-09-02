#include <stddef.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/pkt_cls.h>
#include <linux/errno.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "ebpf_proxy_struct.h"
#include "http_helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define DISABLE_BPF_PRINTK 0

#if DISABLE_BPF_PRINTK == 1
#define bpf_log_printk(fmt, ...) (0)
#else
#define bpf_log_printk(...) bpf_printk(__VA_ARGS__)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 40000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __uint(key_size, sizeof(struct url_value));
    __uint(value_size, sizeof(int));
} url_to_server_map SEC(".maps");

struct backend_conns {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 10000);
    __uint(value_size, sizeof(struct sock_key));
} backend1_conns SEC(".maps"), backend2_conns SEC(".maps"), backend3_conns SEC(".maps"), backend4_conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY_OF_MAPS);
    __uint(max_entries, 4);
    __uint(key_size, sizeof(__u32));
    __array(values, struct backend_conns);
} conn_pool SEC(".maps") = {
    .values = {
        &backend1_conns,
        &backend2_conns,
        &backend3_conns,
        &backend4_conns
    }
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 5000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct sock_key));
} b2c SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 5000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct sock_key));
} c2b SEC(".maps");

SEC("sk_skb/stream_verdict")
int bpf_prog_parser(struct __sk_buff *skb) {
    return skb->len;
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb) {
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    bpf_log_printk("Process packet: local [%pI4:%u] remote: [%pI4:%u]", 
        bpf_ntohl(skb->local_ip4), skb->local_port,
        bpf_ntohl(skb->remote_ip4), bpf_ntohl(skb->remote_port));  

    // print content 
    int len = 128;
    for (int i = 0; i < 16; i++) {
        if (_pull_and_validate_data(skb, &data, &data_end, len - i * 8)) {
            bpf_log_printk("Data: %s", data);
            break;
        }        
    }      

    // check if this is a client packet that already 
    // has an open backend connection
    __u32 port = bpf_ntohl(skb->remote_port);
    struct sock_key *backend_key = bpf_map_lookup_elem(&c2b, &port);
    if (backend_key != NULL) {
        bpf_log_printk("Received a packet from an existing client connection");
        bpf_log_printk("Redirecting to connection [%pI4:%d]", backend_key->ip4, backend_key->port);
        
        int r = bpf_sk_redirect_hash(skb, &sock_map, &backend_key->port, 0);
        if (r == SK_DROP) {
            bpf_log_printk("ERROR: Redirect failed\n");
        }
        return r;
    }

    // check if this is a backend packet that 
    // we can forward to a client connection
    port = skb->local_port;
    struct sock_key *client_key = bpf_map_lookup_elem(&b2c, &port);
    if (client_key != NULL) {
        bpf_log_printk("Received a packet from an existing backend connection");
        bpf_log_printk("Redirecting to connection [%pI4:%d]", client_key->ip4, client_key->port);

        int r = bpf_sk_redirect_hash(skb, &sock_map, &client_key->port, 0);
        if (r == SK_DROP) {
            bpf_log_printk("ERROR: Redirect failed\n");
        }
        return r;
    }

    if (!_pull_and_validate_data(skb, &data, &data_end, 8)) {
        bpf_log_printk("ERROR: Failed to pull data.");
        return SK_PASS;
    }

    // this is an new client connection
    // we just assume this is comes from the client
    struct http_state http;
    if (is_http_request(data, &http)) {
        bpf_log_printk("Received HTTP request");

        // Let's try to read the URL. We set a max size for it
        // First let's check the max size, which depends on the method
        uint32_t method_len = get_method_len(http.state);
        uint32_t max_header_size = method_len + 1 + _MAX_URL_SIZE + 1 + 10;

        if (!_pull_and_validate_data(skb, &data, &data_end, max_header_size)) {
            bpf_log_printk("ERROR: pulling data from skb");
            return SK_DROP;
        }
        struct url_value url;
        __builtin_memset(&url, 0, sizeof(url));

        char final_char = get_url_from_request(data, method_len + 1, max_header_size, http.state, &url);

        int *backend;
        backend = bpf_map_lookup_elem(&url_to_server_map, &url);
        if (backend == NULL) {
            bpf_log_printk("ERROR: unknown URL");
            return SK_DROP;
        }

        // we have received a request
        // fetch an unused backend connection
        struct bpf_elf_map *socks;
        int idx = *backend - 1;
        socks = bpf_map_lookup_elem(&conn_pool, &idx);
        if (socks == NULL) {
            bpf_log_printk("ERROR: Failed to find backend to handle request");
            return SK_DROP;
        }

        // retrieve a new socket key for our connection
        struct sock_key reused_backend_key = { 0 };
        if (bpf_map_pop_elem(socks, &reused_backend_key) < 0) {
            // no open connection that we can reuse
            // forward the packet to the userspace program
            bpf_log_printk("Connection pool is empty. Redirect to userspace.");
            return SK_PASS;
        }

        // assign client req to backend session
        // sock key for the current skb
        struct sock_key new_client_key = { 0 };
        new_client_key.port = bpf_ntohl(skb->remote_port);
        if (bpf_map_update_elem(&c2b, &new_client_key.port, &reused_backend_key, BPF_NOEXIST) < 0) {
            bpf_log_printk("ERROR: Failed to assign client to backend connection");
            return SK_DROP;
        }

        if (bpf_map_update_elem(&b2c, &reused_backend_key.port, &new_client_key, BPF_NOEXIST) < 0) {
            bpf_log_printk("ERROR: Failed to assign backend to client connection");
            return SK_DROP;
        }

        bpf_log_printk("Reuse socket [%pI4:%d->%d] for connection from: %d", reused_backend_key.ip4, reused_backend_key.port, reused_backend_key.backend, bpf_ntohl(skb->remote_port));
        int r = bpf_sk_redirect_hash(skb, &sock_map, &reused_backend_key.port, 0);
        if (r == SK_DROP) {
            bpf_log_printk("ERROR: Redirect failed\n");
        }
        return r;
    }

    bpf_log_printk("ERROR: Unknown packet");
    return SK_DROP;
}

// SEC("sockops")
// int _sock_ops(struct bpf_sock_ops *ops) {
//     int op = (int)ops->op;

//     struct sock_key key = { 0 };

//     // register client connections (client-proxy)
//     if (ops->local_port == 3000) {
//         // key.ip4 = bpf_ntohl(ops->remote_ip4);
//         key.port = bpf_ntohl(ops->remote_port);
//     }
//     else if (bpf_ntohl(ops->remote_port) == 8000) {
//         // key.ip4 = bpf_ntohl(ops->local_ip4);
//         key.port = ops->local_port;
//     }
//     else {
//         return 0;
//     }

//     bpf_log_printk("Process sockops: local [%pI4:%u] remote: [%pI4:%u] op: %d", 
//         bpf_ntohl(ops->local_ip4), ops->local_port,
//         bpf_ntohl(ops->remote_ip4), bpf_ntohl(ops->remote_port), ops->op);

//     if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
//         bpf_log_printk("Add socket with key [%pI4:%d->%d]", key.ip4, key.port, key.backend);

//         bpf_sock_ops_cb_flags_set(ops, ops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
//         if (bpf_sock_hash_update(ops, &sock_map, &key.port, BPF_NOEXIST) < 0) {
//             bpf_log_printk("ERROR: Adding socket failed.");
//         }

//         // put backend connection into queue
//         if (bpf_ntohl(ops->remote_port) == 8000) {
            // struct bpf_elf_map *socks;
            // int idx = 0;
            // socks = bpf_map_lookup_elem(&conn_pool, &idx);
            // if (socks == NULL) {
            //     bpf_log_printk("ERROR: Failed to find queue to put backend connection back in");
            //     return 0;
            // }

            // bpf_log_printk("Enqueuing connection [%pI4:%d]", key.ip4, key.port);
            // if (bpf_map_push_elem(socks, &key, 0) < 0) {
            //     bpf_log_printk("ERROR: Failed to push connection back into queue");
            //     return 0;
            // }
//         }
//     }
//     else if (op == BPF_SOCK_OPS_STATE_CB && ops->args[1] == BPF_TCP_CLOSE && ops->local_port == 3000) {
//         bpf_log_printk("Close client connection [%pI4:%d]", key.ip4, key.port);

//         struct sock_key *client_key = &key;
//         struct sock_key *backend_key;
//         backend_key = bpf_map_lookup_elem(&c2b, &client_key->port);

//         if (backend_key == NULL) {
//             // bpf_log_printk("ERROR: Request with key [%pI4:%d] didn't exist in c2b", client_key->ip4, client_key->port);
//             return 0;
//         }

//         if (bpf_map_delete_elem(&c2b, &client_key->port) < 0) {
//             bpf_log_printk("ERROR: Failed to delete c2b entry with key [%pI4:%d]", client_key->ip4, client_key->port);
//         }

//         if (bpf_map_delete_elem(&b2c, &backend_key->port) < 0) {
//             bpf_log_printk("ERROR: Failed to delete b2c entry with key [%pI4:%d]", backend_key->ip4, backend_key->port);
//         }

//         // put backend connection back into queue
//         struct bpf_elf_map *socks;
//         int idx = backend_key->backend - 1;
//         socks = bpf_map_lookup_elem(&conn_pool, &idx);
//         if (socks == NULL) {
//             bpf_log_printk("ERROR: Failed to find queue to put backend connection back in");
//             return 0;
//         }

//         bpf_log_printk("Enqueuing connection [%pI4:%d]", backend_key->ip4, backend_key->port);
//         if (bpf_map_push_elem(socks, backend_key, 0) < 0) {
//             bpf_log_printk("ERROR: Failed to push connection back into queue");
//             return 0;
//         }
//     }

//     if (op == BPF_SOCK_OPS_STATE_CB) {
//         bpf_log_printk("Socket with key [%pI4:%d] changed state %d | %d | %d | %d", key.ip4, key.port, ops->args[0], ops->args[1], ops->args[2], ops->args[3]);
//     }

//     return 0;
// }