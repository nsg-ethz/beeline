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
#include <sys/socket.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"
#include "ebpf_proxy_struct.h"
#include "http_helpers.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define DISABLE_BPF_PRINTK 1

#if DISABLE_BPF_PRINTK == 1
#define bpf_log_printk(fmt, ...) (0)
#else
#define bpf_log_printk(...) bpf_printk(__VA_ARGS__)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 20);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20);
    __uint(key_size, sizeof(struct url_value));
    __uint(value_size, sizeof(int));
} url_to_server_map SEC(".maps");

SEC("sk_skb")
int bpf_prog_parser(struct __sk_buff *skb) {
    return skb->len;
}

SEC("sk_skb")
int bpf_prog_verdict(struct __sk_buff *skb) {
    int rc = SK_PASS;
    int err;
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;

    // if (!_pull_and_validate_data(skb, &data, &data_end, 8)) {
    if (!_pull_and_validate_data(skb, &data, &data_end, 8)) {
        bpf_log_printk("Error pulling data from skb");
        return SK_DROP;
    }

    struct http_state http;
    int redirect_idx = 0;

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

        int *dst_idx;
        dst_idx = bpf_map_lookup_elem(&url_to_server_map, &url);
        if (!dst_idx) {
            bpf_log_printk("Error getting URL from map");
            redirect_idx = 1;
        } else {
            redirect_idx = *dst_idx;
        }

        bpf_log_printk("Redirecting packet to idx: %d", redirect_idx);
    // } else if (is_http_response(data, &http)) {
    //     bpf_log_printk("Received HTTP response");

    //     uint32_t max_header_size = 8 + 1 + _MAX_STATUS_CODE;

    //     if (!_pull_and_validate_data(skb, &data, &data_end, max_header_size)) {
    //         bpf_log_printk("Error pulling data from skb");
    //         return SK_DROP;
    //     }

    //     __builtin_memcpy(http.code, data + 8 + 1, _MAX_STATUS_CODE);
    //     redirect_idx = 0;
    } else {
        bpf_log_printk("No HTTP packet");
        http.state = NO_HTTP_PACKET;
        redirect_idx = 0;
    }

    int r = bpf_sk_redirect_map(skb, &sock_map, redirect_idx, 0);
    bpf_log_printk("Redirect returned %d\n", r);
    return SK_PASS;
}

SEC("sockops")
int _sock_ops(struct bpf_sock_ops *ops) {
    int op;
    op = (int)ops->op;

    if (ops->local_port != 3000) {
        return 0;
    }

    int key = 0;
    // TCP_CLOSE
    if (op == BPF_SOCK_OPS_STATE_CB && ops->args[1] == BPF_TCP_CLOSE) {
        bpf_log_printk("Socket closed. Delete sockmap entry at key: %d", key);
        bpf_map_delete_elem(&sock_map, &key);
        return 0;
    }

    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB ||
        op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        bpf_log_printk("New socket added with IP src: %u, IP dst: %u",
                   ops->local_ip4, ops->remote_ip4);
        bpf_log_printk("New socket added with TCP src port: %u, TCP dst port: %u",
                   ops->local_port, bpf_ntohl(ops->remote_port));

        bpf_sock_ops_cb_flags_set(ops, ops->bpf_sock_ops_cb_flags |
                                           BPF_SOCK_OPS_STATE_CB_FLAG);
        bpf_sock_map_update(ops, &sock_map, &key, BPF_ANY);
    }

    return 0;
}