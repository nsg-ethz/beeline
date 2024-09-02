// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Sebastiano Miano <mianosebastiano@gmail.com */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

#include "net.h"
#include "ebpf_proxy_struct.h"
#include "ebpf_proxy.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void) {
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }
}

bool restart_backend_conn(int idx, int *connect_socks,
                          struct sockaddr_storage *connect, int sockmap_fd) {

    if (connect_socks[idx] != 0) {
        close(connect_socks[idx]);
    }

    int sock_fd = net_connect_tcp_blocking(&connect[idx], 0);
    if (sock_fd < 0) {
        fprintf(stderr, "Connect to %s failed\n", net_ntop(&connect[idx]));
        return false;
    }
    connect_socks[idx] = sock_fd;
    printf("Connected to %s\n", net_ntop(&connect[idx]));

    int on = 1;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    // {
    //     /* There is a bug in sockmap which prevents it from
    //      * working right when snd buffer is full. Set it to
    //      * gigantic value. */
    //     int val = 32 * 1024 * 1024;
    //     setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
    // }

    int sockmap_idx = idx + 1;
    int val = connect_socks[idx];
    printf("Updating map at index: %d, with val: %d\n", sockmap_idx, val);
    int r = bpf_map_update_elem(sockmap_fd, &sockmap_idx, &val, BPF_ANY);
    if (r != 0) {
        if (errno == EOPNOTSUPP) {
            perror("pushing closed socket to sockmap?");
            return false;
        }
        fprintf(stderr, "bpf_map_update_elem failed\n");
        return false;
    }

    return true;
}

int main(int argc, char **argv) {
    struct ebpf_proxy_bpf *skel;
    int err;

    if (argc < 3) {
        fprintf(stderr,
                "Usage: %s <listen:port> <connect:port> [<connectN:portN>]\n",
                argv[0]);
        exit(1);
    }

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    /* Open BPF application */
    skel = ebpf_proxy_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = ebpf_proxy_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    int cg_fd = open("/sys/fs/cgroup/", __O_DIRECTORY, O_RDONLY);
    if (cg_fd < 0) {
        fprintf(stderr, "failed to set reuseaddr: %s\n", strerror(errno));
        return -1;
    }

    err = bpf_prog_attach(bpf_program__fd(skel->progs._sock_ops), cg_fd,
                          BPF_CGROUP_SOCK_OPS, 0);
    if (err < 0) {
        fprintf(stderr, "failed to attach sockops: %s\n", strerror(errno));
        return -1;
    }

    int sockmap_fd = bpf_map__fd(skel->maps.sock_map);

    err = bpf_prog_attach(bpf_program__fd(skel->progs.bpf_prog_parser),
                          sockmap_fd, BPF_SK_SKB_STREAM_PARSER, 0);

    if (err) {
        fprintf(stderr, "Failed to attach BPF parser program\n");
        goto cleanup;
    }

    err = bpf_prog_attach(bpf_program__fd(skel->progs.bpf_prog_verdict),
                          sockmap_fd, BPF_SK_SKB_STREAM_VERDICT, 0);

    if (err) {
        fprintf(stderr, "Failed to attach BPF verdict program\n");
        goto cleanup;
    }

    printf("BPF programs loaded correctly!\n");

    struct sockaddr_storage listen;
    net_parse_sockaddr(&listen, argv[1]);

    unsigned int tot_conn_socks = argc - 2;

    struct sockaddr_storage *connect = (struct sockaddr_storage *)malloc(
        tot_conn_socks * sizeof(struct sockaddr_storage));
    int *connect_socks = (int *)malloc(tot_conn_socks * sizeof(int));

    for (int i = 0; i < tot_conn_socks; i++) {
        net_parse_sockaddr(&connect[i], argv[i + 2]);
    }

    struct url_value url_to_server[4];
    for (int i = 0; i < 4; i++) {
        bzero(url_to_server[i].url, sizeof(char) * _MAX_URL_SIZE);
    }
    strcpy(url_to_server[0].url, "/server1");
    strcpy(url_to_server[1].url, "/server2");
    strcpy(url_to_server[2].url, "/server3");
    strcpy(url_to_server[3].url, "/server4");

    int url_to_server_fd = bpf_map__fd(skel->maps.url_to_server_map);
    int redirect_idx = 0;
    for (int i = 0; i < 4; i++) {
        redirect_idx = i + 1;
        int r = bpf_map_update_elem(url_to_server_fd, &url_to_server[i],
                                    &redirect_idx, BPF_NOEXIST);
        if (r != 0) {
            fprintf(stderr, "bpf_map_update_elem(url_to_server) failed\n");
            goto cleanup;
        }
    }

    struct pollfd *fds =
        (struct pollfd *)calloc(tot_conn_socks + 1, sizeof(struct pollfd));
    if (fds == NULL) {
        fprintf(stderr, "malloc failed\n");
        goto cleanup;
    }

    int sd = net_bind_tcp(&listen);
    if (sd < 0) {
        fprintf(stderr, "Bind failed\n");
        goto cleanup;
    }

again_accept:;
    // Create new sockets
    for (int i = 0; i < tot_conn_socks; i++) {
        if (!restart_backend_conn(i, connect_socks, connect, sockmap_fd))
            goto cleanup;
    }
    // Check if an event as occurred in the open sockets.
    // If the socket has been closed, let's connect again
    printf("Accepting new connections\n");

    struct sockaddr_storage client;
    int fd = net_accept(sd, &client);

    int on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    {
        /* There is a bug in sockmap which prevents it from
         * working right when snd buffer is full. Set it to
         * gigantic value. */
        int val = 32 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
    }

    printf("New connection accepted\n");

    /* Add socket to SOCKMAP. Otherwise the ebpf won't work. */
    // int idx = 0;
    // int val = fd;
    // int r = bpf_map_update_elem(sockmap_fd, &idx, &val, BPF_ANY);
    // if (r != 0) {
    //     if (errno == EOPNOTSUPP) {
    //         perror("pushing closed socket to sockmap?");
    //         close(fd);
    //         goto again_accept;
    //     }
    //     fprintf(stderr, "bpf_map_update_elem failed\n");
    //     goto cleanup;
    // }

    /* [*] Wait for the socket to close. Let sockmap do the magic. */
    // struct pollfd fds[1] = {
    //     {.fd = fd, .events = POLLRDHUP},
    //     // {.fd = sockmap_fd, .events = POLLRDHUP},
    // };
    // poll(fds, 1, -1);

    while (true) {
        fds[0].fd = fd;
        fds[0].events = POLLRDHUP;

        for (int i = 1; i <= tot_conn_socks; i++) {
            fds[i].fd = connect_socks[i - 1];
            fds[i].events = POLLRDHUP;
        }
        printf("Poll array initialized\n");
        int nfds = poll(fds, tot_conn_socks + 1, -1);

        if (nfds == -1) {
            fprintf(stderr, "Error in poll syscall\n");
            goto cleanup;
        }

        printf("Events Ready: %d\n", nfds);

        for (int i = 0; i < tot_conn_socks + 1; i++) {
            // Check every event
            if (fds[i].revents != 0) {
                if (i == 0) {
                    goto main_socket_err;
                } else {
                    if (!restart_backend_conn(i - 1, connect_socks, connect,
                                              sockmap_fd)) {
                        fprintf(stderr,
                                "Error restarting backend connection for "
                                "server%i\n",
                                i);
                        goto cleanup;
                    }
                }
            }
        }
    }

main_socket_err:;
    /* Was there a socket error? */
    {
        int err;
        socklen_t err_len = sizeof(err);
        int r = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len);
        if (r < 0) {
            fprintf(stderr, "getsockopt failed\n");
            goto cleanup;
        }
        errno = err;
        if (errno) {
            fprintf(stderr, "sockmap fd\n");
        }
    }

    /* Cleanup the entry from sockmap. */
    // idx = 0;
    // r = bpf_map_delete_elem(sockmap_fd, &idx);
    // if (r != 0) {
    //     if (errno == EINVAL) {
    //         fprintf(stderr, "[-] Removing closed sock from sockmap\n");
    //     } else {
    //         fprintf(stderr, "bpf_map_delete_elem failed\n");
    //         goto cleanup;
    //     }
    // }

    close(fd);
    goto again_accept;

cleanup:
    free(connect);
    for (int i = 0; i < tot_conn_socks; i++) {
        close(connect_socks[i]);
    }
    free(connect_socks);
    ebpf_proxy_bpf__destroy(skel);
    return -err;
}