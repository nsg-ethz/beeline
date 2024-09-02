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
    __uint(max_entries, 4000);
    __uint(key_size, sizeof(struct sock_key));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20);
    __uint(key_size, sizeof(struct url_value));
    __uint(value_size, sizeof(int));
} url_to_server_map SEC(".maps");

struct backend_conns {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 1000);
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
} req_map SEC(".maps");

SEC("sk_skb")
int bpf_prog_parser(struct __sk_buff *skb) {
    return skb->len;
}

SEC("sk_skb")
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

    if (!_pull_and_validate_data(skb, &data, &data_end, 8)) {
        bpf_log_printk("Failed to pull data.");
        return SK_PASS;
    }        

    struct http_state http;
    struct sock_key redirect_key = { 0 };

    if (is_http_request(data, &http)) {
        bpf_log_printk("Received HTTP request");

        // Let's try to read the URL. We set a max size for it
        // First let's check the max size, which depends on the method
        uint32_t method_len = get_method_len(http.state);

        uint32_t max_header_size = method_len + 1 + _MAX_URL_SIZE + 1 + 10;

        if (!_pull_and_validate_data(skb, &data, &data_end, max_header_size)) {
            bpf_log_printk("Error pulling data from skb");
            return SK_DROP;
        }
        struct url_value url;
        __builtin_memset(&url, 0, sizeof(url));

        char final_char =
            get_url_from_request(data, method_len + 1, max_header_size, &url);

        int *backend;
        backend = bpf_map_lookup_elem(&url_to_server_map, &url);
        if (!backend) {
            bpf_log_printk("Error getting URL from map");
            return SK_DROP;
        }
        else {
            // we have received a request
            // fetch an unused backend connection
            struct bpf_elf_map *socks;
        	socks = bpf_map_lookup_elem(&conn_pool, backend);
            if (!socks) {
                bpf_log_printk("Error finding backend to handle request");
                return SK_DROP;
            }

            // retrieve a new socket key for our connection
            if (bpf_map_pop_elem(socks, &redirect_key) < 0) {
                // no open connection that we can reuse
                // forward the packet to the userspace program
                bpf_log_printk("Connection pool is empty. Redirect to userspace.");
                return SK_PASS;
            }

            // assign client req to backend session
            // sock key for the current skb
            struct sock_key backend_key = { 0 };
            // backend_key.ip4 = bpf_ntohl(skb->remote_ip4);
            backend_key.port = bpf_ntohl(skb->remote_port);

            if (bpf_map_update_elem(&req_map, &redirect_key, &backend_key, BPF_NOEXIST) < 0) {
                bpf_log_printk("Error assigning client request %d to backend [%pI4:%d]", bpf_ntohl(skb->remote_port), redirect_key.ip4, redirect_key.port);
                return SK_DROP;
            }

            bpf_log_printk("Reuse socket [%pI4:%d] for connection from: %d", redirect_key.ip4, redirect_key.port, bpf_ntohl(skb->remote_port));
        }
    } 
    else if (is_http_response(data, &http)) {
        bpf_log_printk("Received HTTP response");

        struct sock_key backend_key = { 0 };
        // backend_key.ip4 = bpf_ntohl(skb->local_ip4);
        backend_key.port = skb->local_port;

        struct sock_key *client_key;
        client_key = bpf_map_lookup_elem(&req_map, &backend_key);
        if (!client_key) {
            bpf_log_printk("Error looking up client connection for [%pI4:%d]", backend_key.ip4, backend_key.port);
            return SK_DROP;
        }

        redirect_key = *client_key;
    }
    else {
        bpf_log_printk("No HTTP packet");

        struct sock_key backend_key = { 0 };
        // backend_key.ip4 = bpf_ntohl(skb->local_ip4);
        backend_key.port = skb->local_port;
        
        struct sock_key *client_key;
        client_key = bpf_map_lookup_elem(&req_map, &backend_key);
        if (!client_key) {
            bpf_log_printk("Error looking up client connection for [%pI4:%d]", backend_key.ip4, backend_key.port);
            return SK_DROP;
        }

        redirect_key = *client_key;
    }

    bpf_log_printk("Redirect to socket [%pI4:%d]", redirect_key.ip4, redirect_key.port);

    int r = bpf_sk_redirect_hash(skb, &sock_map, &redirect_key, 0);
    bpf_log_printk("Redirect returned %d\n", r);
    return r;
}

SEC("sockops")
int _sock_ops(struct bpf_sock_ops *ops) {
    int op = (int)ops->op;

    struct sock_key key = { 0 };

    // register client connections (client-proxy)
    if (ops->local_port == 3000) {
        // key.ip4 = bpf_ntohl(ops->remote_ip4);
        key.port = bpf_ntohl(ops->remote_port);
    }
    else if (bpf_ntohl(ops->remote_port) == 8000) {
        // key.ip4 = bpf_ntohl(ops->local_ip4);
        key.port = ops->local_port;
    }
    else {
        return 0;
    }

    bpf_log_printk("Process sockops: local [%pI4:%u] remote: [%pI4:%u]", 
        bpf_ntohl(ops->local_ip4), ops->local_port,
        bpf_ntohl(ops->remote_ip4), bpf_ntohl(ops->remote_port));

    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        bpf_log_printk("Add socket with key [%pI4:%d]", key.ip4, key.port);

        bpf_sock_ops_cb_flags_set(ops, ops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
        if (bpf_sock_hash_update(ops, &sock_map, &key, BPF_ANY) < 0) {
            bpf_log_printk("Adding socket failed.");
        }
    }
    else if (op == BPF_SOCK_OPS_STATE_CB) {
        if (ops->args[1] == BPF_TCP_CLOSE || ops->args[1] == BPF_TCP_CLOSE_WAIT) {
            bpf_log_printk("Close socket [%pI4:%d]", key.ip4, key.port);
            // bpf_log_printk("Remove request with key [%pI4:%d]", key.ip4, key.port);

            // if (bpf_map_delete_elem(&req_map, &key) < 0) {
            //     bpf_log_printk("Request with key [%pI4:%d] didn't exist", key.ip4, key.port);
            // }
        } 
        bpf_log_printk("Socket with key [%pI4:%d] changed state %d | %d | %d | %d", key.ip4, key.port, ops->args[0], ops->args[1], ops->args[2], ops->args[3]);
    }

    return 0;
}