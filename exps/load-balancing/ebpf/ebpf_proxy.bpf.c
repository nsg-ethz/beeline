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

#include "ebpf_proxy_struct.h"
#include "http.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define LOG_LEVEL 1

#if LOG_LEVEL == 0
#define bpf_log(fmt, ...) (0)
#define bpf_err(fmt, ...) (0)
#elif LOG_LEVEL == 1
#define bpf_log(...) (0)
#define bpf_err(...) bpf_printk(__VA_ARGS__)
#elif LOG_LEVEL == 2
#define bpf_log(...) bpf_printk(__VA_ARGS__)
#define bpf_err(...) bpf_printk(__VA_ARGS__)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 40000);
    __uint(key_size, sizeof(struct sock_key));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4);
    __uint(key_size, sizeof(struct url_key));
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
    __uint(key_size, sizeof(struct sock_key));
    __uint(value_size, sizeof(struct sock_key));
} b2c SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 5000);
    __uint(key_size, sizeof(struct sock_key));
    __uint(value_size, sizeof(struct sock_key));
} c2b SEC(".maps");

static __always_inline void _skb_extract_key(struct __sk_buff *skb, struct sock_key *key) {
    // key->remote_ip4 = bpf_ntohl(skb->remote_ip4);
    // key->local_ip4 = bpf_ntohl(skb->local_ip4);
    key->remote_port = bpf_ntohl(skb->remote_port);
    key->local_port = skb->local_port;
}

static __always_inline void _ops_extract_key(struct bpf_sock_ops *ops, struct sock_key *key) {
    // key->remote_ip4 = bpf_ntohl(ops->remote_ip4);
    // key->local_ip4 = bpf_ntohl(ops->local_ip4);
    key->remote_port = bpf_ntohl(ops->remote_port);
    key->local_port = ops->local_port;
}

static __always_inline void _copy_sock_key(struct sock_key *src, struct sock_key *dst) {
    dst->remote_ip4 = src->remote_ip4;
    dst->local_ip4 = src->local_ip4;
    dst->remote_port = src->remote_port;
    dst->local_port = src->local_port;
    dst->backend = src->backend;
}

static __always_inline int _try_redirect(struct __sk_buff *skb, struct sock_key *key) {
    bpf_log("Redirecting to connection [%pI4:%d -> %pI4:%d]", key->local_ip4, key->local_port, key->remote_ip4, key->remote_port);
    int r = bpf_sk_redirect_hash(skb, &sock_map, key, 0);
    if (r == SK_DROP) {
        bpf_err("ERROR: Redirect failed\n");
    }
    return r;
}

static __always_inline int _parse_http_hdr(struct __sk_buff *skb, struct http_hdr *hdr) {
    __u32 len = 48;
    // uncommenting this breaks it even using the regular for loop
    // if (len > skb->len) len = skb->len;

    if (bpf_skb_pull_data(skb, len) < 0) {
        return -1;
    }

    char *data_end = (char *)(long)skb->data_end;
    char *data = (char *)(long)skb->data;

    if (data + len > data_end) {
        return -1;
    }

    // hdr->content_length = 8359;
    // hdr->content_length = 400;

    return _parse_http_hdr_line(data, data_end, hdr);

    // __u16 k = 0;
    // bpf_for(k, 0, len) {     
    //     __u16 i = k & 0xFF;
    //     if (i < len && data + i > data_end) break;
    //     bpf_printk("data[i] = %d", data[i]);
    // }

    // this works!
    // for (__u32 i = 0; i < len; i++) {
    //     if (data + i > data_end) break;
    //     bpf_printk("data[i] = %d", data[i]);
    // }

    return 0;
}

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb) {
    return skb->len;

    // this is not working yet
    struct sock_key key = { 0 };
    _skb_extract_key(skb, &key);

    struct sock_key *client_key = bpf_map_lookup_elem(&b2c, &key);
    if (client_key != NULL) {
        return skb->len;
    }

    struct http_hdr hdr = { 0 };
    if (_parse_http_hdr(skb, &hdr) < 0) {
        bpf_err("ERROR: Failed to parse HTTP header");
        return skb->len;
    }

    return hdr.content_length + hdr.header_length;
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb) {
    struct sock_key key = { 0 };
    _skb_extract_key(skb, &key);

    bpf_log("Process packet [%pI4:%u->%pI4:%u (%d)]", 
        key.local_ip4, key.local_port, key.remote_ip4, key.remote_port, key.backend); 

    // check if this is a backend packet that 
    // we can forward to a client connection
    struct sock_key *client_key = bpf_map_lookup_elem(&b2c, &key);
    if (client_key != NULL) {
        bpf_log("Received a packet from an existing backend connection");
        return _try_redirect(skb, client_key);
    }

    // this is an new client connection
    // we just assume this is comes from the client
    struct http_hdr hdr = { 0 };
    if (_parse_http_hdr(skb, &hdr) < 0) {
        bpf_err("ERROR: Failed to parse HTTP header");
        return SK_DROP;
    }

    if (hdr.method == HTTP_NONE) {
        bpf_err("ERROR: Unknown packet");
        return SK_DROP;
    }

    bpf_log("Received HTTP request: %s (%d)", hdr.url, hdr.url_len);

    struct url_key url = { 0 };
    for (int i = 0; i < _MAX_URL_SIZE; i++) url.url[i] = hdr.url[i];

    int *backend;
    backend = bpf_map_lookup_elem(&url_to_server_map, &url);
    if (backend == NULL) {
        bpf_err("ERROR: unknown URL");
        return SK_DROP;
    }

    // check if this is a client packet that already 
    // has an open backend connection
    int c2b_exist = BPF_NOEXIST;
    struct sock_key *backend_key = bpf_map_lookup_elem(&c2b, &key);
    if (backend_key != NULL) {
        if (backend_key->backend == *backend) {
            bpf_log("Received a packet from an existing client connection addressing the same backend");
            return _try_redirect(skb, backend_key);
        }

        bpf_log("Received a packet from an existing client connection addressing a different backend: [%pI4:%u->%pI4:%u (%d)]", backend_key->local_ip4, backend_key->local_port, 
            backend_key->remote_ip4, backend_key->remote_port, 
            backend_key->backend);

        // in a previous request, a different backend was used
        // unassign the backend and client connection
        struct sock_key backend_key_copy;
        _copy_sock_key(backend_key, &backend_key_copy);
        backend_key_copy.backend = 0;
        if (bpf_map_delete_elem(&b2c, &backend_key_copy) < 0) {
            bpf_err("ERROR: Failed to unassign a backend connection");
            return SK_DROP;    
        }

        // put the backend back into the pool
        struct bpf_elf_map *conns;
        int idx = backend_key->backend - 1;
        conns = bpf_map_lookup_elem(&conn_pool, &idx);
        if (conns == NULL) {
            bpf_err("ERROR: Failed to find pool for backend connection");
            return SK_DROP;
        }

        if (bpf_map_push_elem(conns, backend_key, 0) < 0) {
            bpf_err("ERROR: Failed to reenqueue a backend connection");
            return SK_DROP;    
        }

        // we reassign the other way around by setting a new value
        c2b_exist = BPF_ANY;
    }

    // we have received a request
    // fetch an unused backend connection
    struct bpf_elf_map *conns;
    int idx = *backend - 1;
    conns = bpf_map_lookup_elem(&conn_pool, &idx);
    if (conns == NULL) {
        bpf_err("ERROR: Failed to find backend to handle request");
        return SK_DROP;
    }

    // retrieve a new socket key for our connection
    struct sock_key reused_backend_key = { 0 };
    if (bpf_map_pop_elem(conns, &reused_backend_key) < 0) {
        // no open connection that we can reuse
        // forward the packet to the userspace program
        bpf_log("Connection pool is empty. Redirect to userspace.");
        return SK_PASS;
    }

    // assign client req to backend session
    // sock key for the current skb
    if (bpf_map_update_elem(&c2b, &key, &reused_backend_key, c2b_exist) < 0) {
        bpf_err("ERROR: Failed to assign client to backend connection");
        return SK_DROP;
    }

    // in BPF, the data is not copied, so we have to copy the key ourselves
    struct sock_key reused_backend_key_copy;
    _copy_sock_key(&reused_backend_key, &reused_backend_key_copy);
    reused_backend_key_copy.backend = 0;
    bpf_log("B2C update [%pI4:%u->%pI4:%u (%d)]", reused_backend_key_copy.local_ip4, reused_backend_key_copy.local_port, 
            reused_backend_key_copy.remote_ip4, reused_backend_key_copy.remote_port, 
            reused_backend_key_copy.backend);
    if (bpf_map_update_elem(&b2c, &reused_backend_key_copy, &key, BPF_NOEXIST) < 0) {
        bpf_err("ERROR: Failed to assign backend to client connection");
        return SK_DROP;
    }

    bpf_log("Reuse backend connection [%pI4:%u->%pI4:%u (%d)] for client connection: [%pI4:%u->%pI4:%u]", 
        reused_backend_key.local_ip4, reused_backend_key.local_port, 
        reused_backend_key.remote_ip4, reused_backend_key.remote_port, 
        reused_backend_key.backend, 
        key.local_ip4, key.local_port, 
        key.remote_ip4, key.remote_port);
    
    return _try_redirect(skb, &reused_backend_key);
}

// SEC("sockops")
// int _sock_ops(struct bpf_sock_ops *ops) {
//     int op = (int)ops->op;

//     if (ops->local_port != 3000 && bpf_ntohl(ops->remote_port) == 8000) {
//         return 0;
//     }

//     struct sock_key key = { 0 };
//     _ops_extract_key(ops, &key);

//     bpf_log("Process sockops %d for connection: [%pI4:%u->%pI4:%u]", ops->op,
//         key.local_ip4, key.local_port, key.remote_ip4, key.remote_port);

//     if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
//         bpf_log("Add socket");

//         bpf_sock_ops_cb_flags_set(ops, ops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
//         if (bpf_sock_hash_update(ops, &sock_map, &key, BPF_NOEXIST) < 0) {
//             bpf_err("ERROR: Adding socket failed.");
//         }

//         // put backend connection into queue
//         if (key.remote_port == 8000) {
//             struct bpf_elf_map *socks;
//             int idx = 0;
//             socks = bpf_map_lookup_elem(&conn_pool, &idx);
//             if (socks == NULL) {
//                 bpf_err("ERROR: Failed to find queue to put backend connection back in");
//                 return 0;
//             }

//             bpf_log("Enqueuing connection [%pI4:%d]", key.ip4, key.port);
//             if (bpf_map_push_elem(socks, &key, 0) < 0) {
//                 bpf_err("ERROR: Failed to push connection back into queue");
//                 return 0;
//             }
//         }
//     }
//     else if (op == BPF_SOCK_OPS_STATE_CB && ops->args[1] == BPF_TCP_CLOSE && ops->local_port == 3000) {
//         bpf_log("Close client connection [%pI4:%d]", key.ip4, key.port);

//         struct sock_key *client_key = &key;
//         struct sock_key *backend_key;
//         backend_key = bpf_map_lookup_elem(&c2b, &client_key->port);

//         if (backend_key == NULL) {
//             // bpf_err("ERROR: Request with key [%pI4:%d] didn't exist in c2b", client_key->ip4, client_key->port);
//             return 0;
//         }

//         if (bpf_map_delete_elem(&c2b, &client_key->port) < 0) {
//             bpf_err("ERROR: Failed to delete c2b entry with key [%pI4:%d]", client_key->ip4, client_key->port);
//         }

//         if (bpf_map_delete_elem(&b2c, &backend_key->port) < 0) {
//             bpf_err("ERROR: Failed to delete b2c entry with key [%pI4:%d]", backend_key->ip4, backend_key->port);
//         }

//         // put backend connection back into queue
//         struct bpf_elf_map *socks;
//         int idx = backend_key->backend - 1;
//         socks = bpf_map_lookup_elem(&conn_pool, &idx);
//         if (socks == NULL) {
//             bpf_err("ERROR: Failed to find queue to put backend connection back in");
//             return 0;
//         }

//         bpf_log("Enqueuing connection [%pI4:%d]", backend_key->ip4, backend_key->port);
//         if (bpf_map_push_elem(socks, backend_key, 0) < 0) {
//             bpf_err("ERROR: Failed to push connection back into queue");
//             return 0;
//         }
//     }

//     if (op == BPF_SOCK_OPS_STATE_CB) {
//         bpf_log("Socket with key [%pI4:%d] changed state %d | %d | %d | %d", key.ip4, key.port, ops->args[0], ops->args[1], ops->args[2], ops->args[3]);
//     }

//     return 0;
// }