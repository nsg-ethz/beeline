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
#include <signal.h>

#include "net.h"
#include "ebpf_proxy_struct.h"
#include "ebpf_proxy.skel.h"

struct ebpf_proxy_bpf *SKEL;
int cg_fd;
const int MAX_NUM_CONN = 1000;

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

static void bpf_detach(int sig) {
    printf("Detaching BPF programs...\n");
    int err = bpf_prog_detach(cg_fd, BPF_CGROUP_SOCK_OPS);
    if (err) {
        fprintf(stderr, "Failed to detach sockops\n");
    }

    ebpf_proxy_bpf__destroy(SKEL);

    exit(0);
}

int start_backend_conn(int idx, struct sockaddr_storage *backend_addrss, int sockmap_fd) {
    int sd = net_connect_tcp_blocking(&backend_addrss[idx], 0);
    if (sd < 0) {
        fprintf(stderr, "Connect to %s failed\n", net_ntop(&backend_addrss[idx]));
        return -1;
    }
    
    printf("Connected to %s\n", net_ntop(&backend_addrss[idx]));

    return sd;
}

int parse_backend(char* req) {
    const char* server_x_req = "GET /server";
    if (strlen(req) <= strlen(server_x_req)) {
        return -1;
    }

    if (strncmp(req, server_x_req, strlen(server_x_req)) == 0) {
        int backend = req[strlen(server_x_req)] - '0';
        return backend;
    }

    return -1;
}

int main(int argc, char **argv) {
    // make sure we properly detach all BPF programs
    signal(SIGINT, bpf_detach);

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
    SKEL = ebpf_proxy_bpf__open();
    if (!SKEL) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load & verify BPF programs */
    err = ebpf_proxy_bpf__load(SKEL);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    cg_fd = open("/sys/fs/cgroup/", __O_DIRECTORY, O_RDONLY);
    if (cg_fd < 0) {
        fprintf(stderr, "failed to set reuseaddr: %s\n", strerror(errno));
        return -1;
    }

    err = bpf_prog_attach(bpf_program__fd(SKEL->progs._sock_ops), cg_fd,
                          BPF_CGROUP_SOCK_OPS, 0);
    if (err < 0) {
        fprintf(stderr, "failed to attach sockops: %s\n", strerror(errno));
        return -1;
    }

    int sockmap_fd = bpf_map__fd(SKEL->maps.sock_map);

    err = bpf_prog_attach(bpf_program__fd(SKEL->progs.bpf_prog_parser),
                          sockmap_fd, BPF_SK_SKB_STREAM_PARSER, 0);

    if (err) {
        fprintf(stderr, "Failed to attach BPF parser program\n");
        goto cleanup;
    }

    err = bpf_prog_attach(bpf_program__fd(SKEL->progs.bpf_prog_verdict),
                          sockmap_fd, BPF_SK_SKB_STREAM_VERDICT, 0);

    if (err) {
        fprintf(stderr, "Failed to attach BPF verdict program\n");
        goto cleanup;
    }

    printf("BPF programs loaded correctly!\n");

    struct sockaddr_storage listen;
    net_parse_sockaddr(&listen, argv[1]);

    unsigned int num_backends = argc - 2;
    struct sockaddr_storage *backend_addrs = (struct sockaddr_storage *)malloc(num_backends * sizeof(struct sockaddr_storage));
    for (int i = 0; i < num_backends; i++) {
        net_parse_sockaddr(&backend_addrs[i], argv[i + 2]);
    }

    struct url_value url_to_server[4];
    for (int i = 0; i < 4; i++) {
        bzero(url_to_server[i].url, sizeof(char) * _MAX_URL_SIZE);
    }
    strcpy(url_to_server[0].url, "/server1");
    strcpy(url_to_server[1].url, "/server2");
    strcpy(url_to_server[2].url, "/server3");
    strcpy(url_to_server[3].url, "/server4");

    int url_to_server_fd = bpf_map__fd(SKEL->maps.url_to_server_map);
    for (int i = 0; i < 4; i++) {
        int backend = i + 1;
        int r = bpf_map_update_elem(url_to_server_fd, &url_to_server[i],
                                    &backend, BPF_NOEXIST);
        if (r != 0) {
            fprintf(stderr, "bpf_map_update_elem(url_to_server) failed\n");
            goto cleanup;
        }
    }

    int b2c_fd = bpf_map__fd(SKEL->maps.b2c);
    int c2b_fd = bpf_map__fd(SKEL->maps.c2b);

    // prepare our sockets structure
    // the first `num_backends` are our backend (proxy-server) connections
    // the next n sockets are our frontend (client-proxy) connections
    unsigned int num_fds = 0;
    struct pollfd *fds = (struct pollfd *)calloc(MAX_NUM_CONN, sizeof(struct pollfd));
    if (fds == NULL) {
        fprintf(stderr, "malloc failed\n");
        goto cleanup;
    }

    // start listening to incomming connections
    int lfd = net_bind_tcp(&listen);
    if (lfd < 0) {
        fprintf(stderr, "Bind failed\n");
        goto cleanup;
    }

accept:
    if (num_fds == MAX_NUM_CONN) {
        printf("No new connections are accepted. Polling...");
        goto poll;
    }

    struct sockaddr_storage client;
    socklen_t client_len = sizeof(struct sockaddr_storage);
    int fd = accept(lfd, (struct sockaddr *)&client, &client_len);
    if (fd < 0) {
        // no new connections
        // due to an error?
        if (errno == EAGAIN) {
            // just no new connection request poll again
            goto poll;
        }

        printf("Error accepting new connections: %s\n", strerror(errno));
        goto cleanup;
    }

    int on = 1;
    int r = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
    if (r < 0) {
        PFATAL("setsockopt(SO_KEEPALIVE)");
    }

    on = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

    {
        /* There is a bug in sockmap which prevents it from
         * working right when snd buffer is full. Set it to
         * gigantic value. */
        int val = 32 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val));
    }

    struct sockaddr_in client_addr;
    int len = sizeof(client_addr);
    if (getpeername(fd, (struct sockaddr *)&client_addr, (socklen_t*)&len) < 0) {
        printf("Error getting peer name: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("New connection accepted: [%s:%d] socket: %d\n", inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port), fd);

    fds[num_fds].fd = fd;
    fds[num_fds].events = POLLIN|POLLRDHUP|POLLHUP|POLLERR;
    num_fds++;

poll:
    // printf("Polling...\n");
    int nfds = poll(fds, num_fds, 0.1);

    if (nfds == -1) {
        fprintf(stderr, "Error in poll syscall\n");
        goto cleanup;
    }
    else if (nfds == 0) {
        goto accept;
    }

    struct pollfd *new_fds = (struct pollfd *)calloc(MAX_NUM_CONN, sizeof(struct pollfd));
    unsigned int new_num_fds = 0;

    for (int i = 0; i < num_fds; i++) {
        if (fds[i].revents & POLLIN) {
            size_t buf_len = 1024;
            char buf[buf_len];
            memset(buf, 0, buf_len);

            // read the entire request
            ssize_t len = read(fds[i].fd, buf, buf_len);
            size_t req_len = strlen(buf);

            // EAGAIN means we have to wait for eBPF verdict first
            if (len < 0 && errno != EAGAIN) {
                printf("Error reading socket: %s\n", strerror(errno));
                close(fds[i].fd);
                continue;
            }
            
            // if we couldn't read yet, but also don't have an error
            // we will just try again :)
            if (len > 0) {
                printf("Received request length %ld after reading %ld: %s\n", req_len, len, buf);

                // we received a new request but don't 
                // have a free connection in the pool
                int backend = parse_backend(buf);
                if (backend < 0) {
                    printf("Invalid request: %s\n", buf);
                    continue;
                }

                // valid request, get the client connection
                struct sockaddr_in client_addr;
                len = sizeof(client_addr);
                if (getpeername(fds[i].fd, (struct sockaddr *)&client_addr, (socklen_t*)&len) < 0) {
                    printf("Error getting peer name: %s\n", strerror(errno));
                    goto cleanup;
                }

                int sd = start_backend_conn(backend-1, backend_addrs, sockmap_fd);
                printf("Established a new connection to backend %d: %d\n", backend, sd);

                struct sockaddr_in backend_addr;
                if (getsockname(sd, (struct sockaddr *)&backend_addr, (socklen_t*)&len) < 0) {
                    printf("Error getting socket name: %s\n", strerror(errno));
                    goto cleanup;
                }

                struct sock_key client_key = { 0 };
                // client_key.ip4 = client_addr.sin_addr.s_addr;
                client_key.port = htons(client_addr.sin_port);

                struct sock_key backend_key = { 0 };
                backend_key.backend = backend;
                // backend_key.ip4 = backend_addr.sin_addr.s_addr;
                backend_key.port = htons(backend_addr.sin_port);
                printf("Assign backend connection [%s:%d] to client connection: [%s:%d]\n", inet_ntoa(backend_addr.sin_addr), backend_key.port, inet_ntoa(client_addr.sin_addr), client_key.port);

                // book keeping
                if (bpf_map_update_elem(c2b_fd, &client_key.port, &backend_key, BPF_NOEXIST) < 0) {
                    fprintf(stderr, "bpf_map_update_elem(c2b) failed: %s\n", strerror(errno));
                    goto cleanup;
                }

                if (bpf_map_update_elem(b2c_fd, &backend_key.port, &client_key, BPF_NOEXIST) < 0) {
                    fprintf(stderr, "bpf_map_update_elem(b2c) failed: %s\n", strerror(errno));
                    goto cleanup;
                }

                size_t res_len = 0;
                do {
                    len = write(sd, buf+res_len, req_len-res_len);
                    if (len < 0) {
                        // the socket might not be ready
                        continue;
                    }
                    
                    if (len == 0) {
                        // we sent the msg
                        break;
                    }
                    res_len += len;
                } while (res_len < req_len);
                printf("Redirected request of length %ld to backend\n", res_len);
            }
        }

        if (fds[i].revents & POLLRDHUP || fds[i].revents & POLLHUP || fds[i].revents & POLLERR) {
            printf("Closing socket %d\n", fds[i].fd);
            shutdown(fds[i].fd, SHUT_RDWR);
            close(fds[i].fd);
        }
        else {
            // we want to poll this fd again
            new_fds[new_num_fds] = fds[i];
            new_num_fds++;
        }
    }

    memset(fds, 0, num_fds);
    for (int i = 0; i < new_num_fds; i++) {
        fds[i] = new_fds[i];
        fds[i].events = POLLIN|POLLRDHUP|POLLHUP|POLLERR;
    }
    num_fds = new_num_fds;
    free(new_fds);

    printf("Got %d open sockets\n", num_fds);
    goto accept;

cleanup:
    for (int i = 0; i < num_fds; i++) {
        close(fds[i].fd);
    }
    free(fds);
    free(backend_addrs);
    ebpf_proxy_bpf__destroy(SKEL);
    return -err;
}