// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Sebastiano Miano <mianosebastiano@gmail.com */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/bpf.h>
#include <linux/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

#include "net.h"
#include "ebpf_proxy_struct.h"
#include "ebpf_proxy.skel.h"

struct ebpf_proxy_bpf *SKEL;
int cg_fd;
const int MAX_NUM_CONN = 10000;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
    return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void) {
    struct rlimit rlim_mem = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim_mem) < 0) {
        fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }

    struct rlimit rlim_file = {
        .rlim_cur = 8192,
        .rlim_max = 8192,
    };
    if (setrlimit(RLIMIT_NOFILE, &rlim_file) < 0) {
        fprintf(stderr, "Failed to increase RLIMIT_NOFILE limit!\n");
        exit(1);
    }
}

static void bpf_detach(int sig) {
    // printf("Detaching BPF programs...\n");
    // int err = bpf_prog_detach(cg_fd, BPF_CGROUP_SOCK_OPS);
    // if (err) {
    //     fprintf(stderr, "Failed to detach sockops\n");
    // }

    // ebpf_proxy_bpf__destroy(SKEL);

    exit(0);
}

int get_sock_key(int fd, struct sock_key *key) {
    memset(key, 0, sizeof(struct sock_key));

    struct sockaddr_in addr;
    int len = sizeof(addr);
    int res = getsockname(fd, (struct sockaddr *)&addr, (socklen_t*)&len);
    if (res < 0) return res;

    // key->local_ip4 = ntohl(addr.sin_addr.s_addr);
    key->local_port = ntohs(addr.sin_port);

    res = getpeername(fd, (struct sockaddr *)&addr, (socklen_t*)&len);
    if (res < 0) return res;

    // key->remote_ip4 = ntohl(addr.sin_addr.s_addr);
    key->remote_port = ntohs(addr.sin_port);

    return 0;
}

int setup_conn(int fd) {
    {
        /* There is a bug in sockmap which prevents it from
         * working right when snd buffer is full. Set it to
         * gigantic value. */
        int val = 32 * 1024 * 1024;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &val, sizeof(val)) < 0) {
            PFATAL("setsockopt(SO_SNDBUF)");
        }

        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val)) < 0) {
            PFATAL("setsockopt(SO_RCVBUF)");
        }
    }

    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0) {
        PFATAL("setsockopt(SO_KEEPALIVE)");
    }

    // if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
    //     PFATAL("setsockopt(SO_REUSEADDR)");
    // }

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0) {
        PFATAL("setsockopt(TCP_NODELAY)");
    }

    return 0;
}

int start_backend_conn(int backend, struct sockaddr_storage *backend_addrss, int sockmap_fd, struct sock_key* backend_key) {
    int idx = backend-1;
    int fd = net_connect_tcp_blocking(&backend_addrss[idx], 0);
    if (fd < 0) {
        fprintf(stderr, "Connect to %s failed\n", net_ntop(&backend_addrss[idx]));
        return -1;
    }

    if (setup_conn(fd) < 0) {
        fprintf(stderr, "Error setting up backend connection\n");
        return -1;
    }

    get_sock_key(fd, backend_key);
    backend_key->backend = backend;

    return fd;
}

int accept_client_conn(int lfd, int sockmap_fd, struct sock_key* client_key) {
    struct sockaddr_storage client;
    socklen_t client_len = sizeof(struct sockaddr_storage);
    int fd = accept(lfd, (struct sockaddr *)&client, &client_len);

    if (fd < 0) {
        if (errno != EAGAIN) {
            fprintf(stderr, "Error accepting new connection.");
        }
        return fd;
    }

    if (setup_conn(fd) < 0) {
        fprintf(stderr, "Error setting up client connection.");
        return -1;
    }

    get_sock_key(fd, client_key);

    return fd;
}

int add_to_sockmap(int sockmap_fd, int fd, struct sock_key *key) {
    printf("Adding socket with key: [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d]\n", 
            (key->local_ip4 >> 24) & 0xff, (key->local_ip4 >> 16) & 0xff, (key->local_ip4 >> 8) & 0xff, key->local_ip4 & 0xff, key->local_port,
            (key->remote_ip4 >> 24) & 0xff, (key->remote_ip4 >> 16) & 0xff, (key->remote_ip4 >> 8) & 0xff, key->remote_ip4 & 0xff, key->remote_port);
    
    if (bpf_map_update_elem(sockmap_fd, key, &fd, BPF_NOEXIST) < 0) {
        if (errno == EOPNOTSUPP) {
            fprintf(stderr, "pushing closed socket to sockmap?\n");
        }

        fprintf(stderr, "bpf_map_update_elem(sock_map) failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int assign_client_to_backend(int c2b_fd, int b2c_fd, struct sock_key* client_key, struct sock_key* backend_key) {
    // the client_key may already exist in c2b, because the connection
    // might have requested a different backend before
    if (bpf_map_update_elem(c2b_fd, client_key, backend_key, BPF_ANY) < 0) {
        fprintf(stderr, "bpf_map_update_elem(c2b) failed: %s\n", strerror(errno));
        return -1;
    }

    // when retrieving a client connection given a backend connection
    // we don't know which backend was addressed, so we set backend to 0
    int backend = backend_key->backend;
    backend_key->backend = 0;
    if (bpf_map_update_elem(b2c_fd, backend_key, client_key, BPF_ANY) < 0) {
        fprintf(stderr, "bpf_map_update_elem(b2c) failed: %s\n", strerror(errno));
        return -1;
    }
    backend_key->backend = backend;

    printf("Assign client connection [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d] to [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d]\n", 
        (client_key->local_ip4 >> 24) & 0xff, (client_key->local_ip4 >> 16) & 0xff, (client_key->local_ip4 >> 8) & 0xff, client_key->local_ip4 & 0xff, client_key->local_port,
        (client_key->remote_ip4 >> 24) & 0xff, (client_key->remote_ip4 >> 16) & 0xff, (client_key->remote_ip4 >> 8) & 0xff, client_key->remote_ip4 & 0xff, client_key->remote_port,
        (backend_key->local_ip4 >> 24) & 0xff, (backend_key->local_ip4 >> 16) & 0xff, (backend_key->local_ip4 >> 8) & 0xff, backend_key->local_ip4 & 0xff, backend_key->local_port,
        (backend_key->remote_ip4 >> 24) & 0xff, (backend_key->remote_ip4 >> 16) & 0xff, (backend_key->remote_ip4 >> 8) & 0xff, backend_key->remote_ip4 & 0xff, backend_key->remote_port);

    return 0;
}

int parse_backend(char* req) {
    const char* get_server_x = "GET /server";
    if (strlen(req) <= strlen(get_server_x)) {
        return -1;
    }

    if (strncmp(req, get_server_x, strlen(get_server_x)) == 0) {
        int backend = req[strlen(get_server_x)] - '0';
        return backend;
    }

    const char* post_server_x = "POST /server";
    if (strncmp(req, post_server_x, strlen(post_server_x)) == 0) {
        int backend = req[strlen(post_server_x)] - '0';
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
        return -1;
    }

    cg_fd = open("/sys/fs/cgroup/", __O_DIRECTORY, O_RDONLY);
    if (cg_fd < 0) {
        fprintf(stderr, "failed to set reuseaddr: %s\n", strerror(errno));
        return -1;
    }

    // err = bpf_prog_attach(bpf_program__fd(SKEL->progs._sock_ops), cg_fd,
    //                       BPF_CGROUP_SOCK_OPS, 0);
    // if (err < 0) {
    //     fprintf(stderr, "failed to attach sockops: %s\n", strerror(errno));
    //     return -1;
    // }

    int sockmap_fd = bpf_map__fd(SKEL->maps.sock_map);

    err = bpf_prog_attach(bpf_program__fd(SKEL->progs.bpf_prog_parser),
                          sockmap_fd, BPF_SK_SKB_STREAM_PARSER, 0);

    if (err) {
        fprintf(stderr, "Failed to attach BPF parser program\n");
        return -1;
    }

    err = bpf_prog_attach(bpf_program__fd(SKEL->progs.bpf_prog_verdict),
                          sockmap_fd, BPF_SK_SKB_STREAM_VERDICT, 0);

    if (err) {
        fprintf(stderr, "Failed to attach BPF verdict program\n");
        return -1;
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
            return -1;
        }
    }

    int b2c_fd = bpf_map__fd(SKEL->maps.b2c);
    int c2b_fd = bpf_map__fd(SKEL->maps.c2b);

    // start listening to incomming connections
    int num_fds = 0;
    int lfd = net_bind_tcp(&listen);
    if (lfd < 0) {
        fprintf(stderr, "Bind failed\n");
        goto cleanup;
    }

    struct pollfd *fds = (struct pollfd *)calloc(MAX_NUM_CONN, sizeof(struct pollfd));
    if (fds == NULL) {
        fprintf(stderr, "malloc failed\n");
        goto cleanup;
    }

    int backend1_conns_fd = bpf_map__fd(SKEL->maps.backend1_conns);
    int backend2_conns_fd = bpf_map__fd(SKEL->maps.backend2_conns);
    int backend3_conns_fd = bpf_map__fd(SKEL->maps.backend3_conns);
    int backend4_conns_fd = bpf_map__fd(SKEL->maps.backend4_conns);

    // for (int i = 0; i < 1000; i++) {
    //     struct sock_key key = { 0 };
    //     int bd = start_backend_conn(0, backend_addrs, sockmap_fd, &key);

    //     int r = bpf_map_update_elem(backend1_conns_fd, NULL, &key, BPF_ANY);
    //     if (r != 0) {
    //         fprintf(stderr, "bpf_map_update_elem(backend1_conns) failed: %s\n", strerror(errno));
    //         goto cleanup;
    //     }
    // }

accept:
    if (num_fds == MAX_NUM_CONN) {
        printf("No new connections are accepted.\n");
        goto poll;
    }

    struct sock_key client_key = { 0 };
    int cd = accept_client_conn(lfd, sockmap_fd, &client_key);
    if (cd < 0) {
        // no new connections
        // due to an error?
        if (errno == EAGAIN) {
            // just no new connection request -> poll again
            goto poll;
        }

        printf("Error accepting new connections: %s\n", strerror(errno));
        goto cleanup;
    }

    fds[num_fds].fd = cd;
    fds[num_fds].events = POLLRDHUP|POLLHUP|POLLERR|POLLIN;
    num_fds++;

poll:
    // // no polling
    // goto accept;
    int nfds = poll(fds, num_fds, 0.1);

    if (nfds == -1) {
        fprintf(stderr, "Error in poll syscall\n");
        goto cleanup;
    }
    else if (nfds == 0) {
        goto accept;
    }

    int num_fds_new = 0;
    struct pollfd *fds_new = (struct pollfd *)calloc(MAX_NUM_CONN, sizeof(struct pollfd));
    if (fds_new == NULL) {
        fprintf(stderr, "malloc failed\n");
        goto cleanup;
    }
    
    for (int i = 0; i < num_fds; i++) {
        if (fds[i].revents & POLLIN) {
            size_t buf_len = 128 * 1024;
            char buf[buf_len];
            memset(buf, 0, buf_len);

            // read the entire request
            ssize_t len = recv(fds[i].fd, buf, buf_len, MSG_DONTWAIT);
            size_t req_len = strlen(buf);

            // EAGAIN means we have to wait for eBPF verdict first
            if (len < 0 && errno != EAGAIN) {
                printf("Error reading socket: %s\n", strerror(errno));
                close(fds[i].fd);
                continue;
            }

            // TODO: continue observing socket breaks the "on demand" solution
            fds_new[num_fds_new].fd = fds[i].fd;
            fds_new[num_fds_new].events = POLLRDHUP|POLLHUP|POLLERR;
            num_fds_new++;

            // if we couldn't read yet, but also don't have an error
            // we will just try again :)
            if (len > 0) {
                printf("Received request length %ld after reading %ld: %s\n", req_len, len, buf);

                // we received a new request but don't 
                // have a free connection in the pool
                int backend = parse_backend(buf);
                if (backend < 1) {
                    printf("Invalid request: %s\n", buf);
                    continue;
                }

                // valid request -> start backend connections
                // we start all 4 connections right away, because
                // contacting userspace later is buggy
                struct sock_key backend_key = { 0 };
                int bd = -1;
                for (int i = 1; i < 5; i++) {
                    struct sock_key key = { 0 };
                    int fd = start_backend_conn(i, backend_addrs, sockmap_fd, &key);
                    printf("Established a new connection to backend %d: %d\n", key.backend, fd);

                    add_to_sockmap(sockmap_fd, fd, &key);
                    if (i == backend) {
                        backend_key = key;
                        bd = fd;
                    }
                    else {
                        int conns_fd = -1;
                        switch (i) {
                            case 1: conns_fd = backend1_conns_fd; break;
                            case 2: conns_fd = backend2_conns_fd; break;
                            case 3: conns_fd = backend3_conns_fd; break;
                            case 4: conns_fd = backend4_conns_fd; break;
                        }

                        if (bpf_map_update_elem(conns_fd, NULL, &key, BPF_ANY) < 0) {
                            fprintf(stderr, "bpf_map_update_elem(backend1_conns) failed: %s\n", strerror(errno));
                            goto cleanup;
                        }
                    }
                }

                // book keeping
                struct sock_key client_key = { 0 };
                get_sock_key(fds[i].fd, &client_key);

                if (assign_client_to_backend(c2b_fd, b2c_fd, &client_key, &backend_key) < 0) {
                    goto cleanup;
                }

                add_to_sockmap(sockmap_fd, fds[i].fd, &client_key);

                size_t res_len = 0;
                do {
                    len = write(bd, buf+res_len, req_len-res_len);
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
        
        if (fds[i].revents & POLLRDHUP || fds[i].revents & POLLHUP) {
            printf("Client connection closed\n");
            close(fds[i].fd);
        }
    }

    free(fds);
    fds = fds_new;
    num_fds = num_fds_new;

    goto accept;

cleanup:
    close(lfd);
    for (int i = 0; i < num_fds; i++) {
        close(fds[i].fd);
    }
    free(backend_addrs);
    ebpf_proxy_bpf__destroy(SKEL);
    return -err;
}