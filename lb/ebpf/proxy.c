// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Sebastiano Miano <mianosebastiano@gmail.com */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
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
#include <pthread.h>

#include "net.h"
#include "proxy_struct.h"
#include "proxy.skel.h"

#define LOG_LEVEL 1

#if LOG_LEVEL == 0
#define print_log(...) (void)0
#define print_err(...) (void)0
#elif LOG_LEVEL == 1
#define print_log(...) (void)0
#define print_err(...) fprintf(stderr, __VA_ARGS__)
#elif LOG_LEVEL == 2
#define print_log(...) fprintf(stdout, __VA_ARGS__)
#define print_err(...) fprintf(stderr, __VA_ARGS__)
#endif

struct proxy_bpf *SKEL;
int cg_fd;
int sockmap_fd;
struct sockaddr_storage addr;

const int NUM_WORKERS = 1;
const int MAX_NUM_CONN = 1000;
const int MAX_EVENTS = MAX_NUM_CONN;
struct sockaddr_storage *backend_addrs;
int num_conn_pool[4] = { 0 };

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
        print_err("Failed to increase RLIMIT_MEMLOCK limit!\n");
        exit(1);
    }

    // struct rlimit rlim_file = {
    //     .rlim_cur = 8192,
    //     .rlim_max = 8192,
    // };
    // if (setrlimit(RLIMIT_NOFILE, &rlim_file) < 0) {
    //     print_err("Failed to increase RLIMIT_NOFILE limit!\n");
    //     exit(1);
    // }
}

// static void bpf_detach(int sig) {
    // printf("Detaching BPF programs...\n");
    // int err = bpf_prog_detach(cg_fd, BPF_CGROUP_SOCK_OPS);
    // if (err) {
    //     print_err("Failed to detach sockops\n");
    // }

    // proxy_bpf__destroy(SKEL);

//     exit(0);
// }

int get_sock_key(int fd, struct sock_key *key) {
    memset(key, 0, sizeof(struct sock_key));

    struct sockaddr_in addr;
    int len = sizeof(addr);
    int res = getsockname(fd, (struct sockaddr *)&addr, (socklen_t*)&len);
    if (res < 0) return res;

    key->local_ip4 = ntohl(addr.sin_addr.s_addr);
    key->local_port = ntohs(addr.sin_port);

    res = getpeername(fd, (struct sockaddr *)&addr, (socklen_t*)&len);
    if (res < 0) return res;

    key->remote_ip4 = ntohl(addr.sin_addr.s_addr);
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
            print_err("setsockopt(SO_SNDBUF)");
        }

        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &val, sizeof(val)) < 0) {
            print_err("setsockopt(SO_RCVBUF)");
        }
    }

    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) < 0) {
        print_err("setsockopt(SO_KEEPALIVE)");
    }

    // if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) < 0) {
    //     print_err("setsockopt(SO_REUSEADDR)");
    // }

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) < 0) {
        print_err("setsockopt(TCP_NODELAY)");
    }

    return 0;
}

int start_backend_conn(int backend, struct sockaddr_storage *backend_addrss, int sockmap_fd, struct sock_key* backend_key) {
    int idx = backend-1;
    int fd = net_connect_tcp_blocking(&backend_addrss[idx], 0);
    if (fd < 0) {
        print_err("Connect to %s failed\n", net_ntop(&backend_addrss[idx]));
        return -1;
    }

    if (setup_conn(fd) < 0) {
        print_err("Error setting up backend connection\n");
        return -1;
    }

    get_sock_key(fd, backend_key);
    backend_key->backend = backend;

    num_conn_pool[idx]++;

    return fd;
}

int accept_client_conn(int lfd, int sockmap_fd, struct sock_key* client_key) {
    struct sockaddr_storage client;
    socklen_t client_len = sizeof(struct sockaddr_storage);
    int fd = accept(lfd, (struct sockaddr *)&client, &client_len);

    if (fd < 0) {
        if (errno != EAGAIN) {
            print_err("Error accepting new connection.");
        }
        return fd;
    }

    if (setup_conn(fd) < 0) {
        print_err("Error setting up client connection.");
        return -1;
    }

    get_sock_key(fd, client_key);

    print_log("Accepted new client connection [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d]\n", 
        (client_key->local_ip4 >> 24) & 0xff, (client_key->local_ip4 >> 16) & 0xff, (client_key->local_ip4 >> 8) & 0xff, client_key->local_ip4 & 0xff, client_key->local_port,
        (client_key->remote_ip4 >> 24) & 0xff, (client_key->remote_ip4 >> 16) & 0xff, (client_key->remote_ip4 >> 8) & 0xff, client_key->remote_ip4 & 0xff, client_key->remote_port);

    return fd;
}

int add_to_sockmap(int sockmap_fd, int fd, struct sock_key *key) {
    print_log("Adding socket with key: [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d]\n", 
            (key->local_ip4 >> 24) & 0xff, (key->local_ip4 >> 16) & 0xff, (key->local_ip4 >> 8) & 0xff, key->local_ip4 & 0xff, key->local_port,
            (key->remote_ip4 >> 24) & 0xff, (key->remote_ip4 >> 16) & 0xff, (key->remote_ip4 >> 8) & 0xff, key->remote_ip4 & 0xff, key->remote_port);
    
    if (bpf_map_update_elem(sockmap_fd, key, &fd, BPF_ANY) < 0) {
        if (errno == EOPNOTSUPP) {
            print_err("pushing closed socket to sockmap?\n");
        }

        print_err("bpf_map_update_elem(sock_map) failed: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

int assign_client_to_backend(int c2b_fd, int b2c_fd, struct sock_key* client_key, struct sock_key* backend_key) {
    print_log("Assign client connection [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d] to [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d]\n", 
        (client_key->local_ip4 >> 24) & 0xff, (client_key->local_ip4 >> 16) & 0xff, (client_key->local_ip4 >> 8) & 0xff, client_key->local_ip4 & 0xff, client_key->local_port,
        (client_key->remote_ip4 >> 24) & 0xff, (client_key->remote_ip4 >> 16) & 0xff, (client_key->remote_ip4 >> 8) & 0xff, client_key->remote_ip4 & 0xff, client_key->remote_port,
        (backend_key->local_ip4 >> 24) & 0xff, (backend_key->local_ip4 >> 16) & 0xff, (backend_key->local_ip4 >> 8) & 0xff, backend_key->local_ip4 & 0xff, backend_key->local_port,
        (backend_key->remote_ip4 >> 24) & 0xff, (backend_key->remote_ip4 >> 16) & 0xff, (backend_key->remote_ip4 >> 8) & 0xff, backend_key->remote_ip4 & 0xff, backend_key->remote_port);

    // when retrieving a client connection given a backend connection
    // we don't know which backend was addressed, so we set backend to 0
    int backend = backend_key->backend;
    backend_key->backend = 0;
    if (bpf_map_update_elem(b2c_fd, backend_key, client_key, BPF_NOEXIST) < 0) {
        print_err("bpf_map_update_elem(b2c) failed: %s\n", strerror(errno));
        exit(-1);
    }
    backend_key->backend = backend;

    if (bpf_map_update_elem(c2b_fd, client_key, backend_key, BPF_NOEXIST) < 0) {
        print_err("bpf_map_update_elem(c2b) failed: %s\n", strerror(errno));
        exit(-1);
    }

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

int parse_http_hdr_len(const char* hdr) {
    const char *sep = "\r\n\r\n";
    char *next = strstr(hdr, sep);
    if (next != NULL) {
        return next-hdr + strlen(sep);
    }

    return -1;
}

const void* parse_http_hdr(const char *hdr, const char *key) {
    int name_len = strlen(key) + 2;
    char name[name_len + 1];
    snprintf(name, name_len+1, "%s: ", key);

    const char *line = hdr;
    const char *sep = "\r\n";
    int sep_len = 2;
    while (line) {
        char *next = strstr(line, sep);

        if (next == NULL) break;
        if (strncasecmp(line, name, name_len) == 0) {
            return line + name_len;
        }
    
        line = next ? (next+sep_len) : NULL;
    }

    return NULL;
}

void* worker(void* arg) {
    int b2c_fd = bpf_map__fd(SKEL->maps.b2c);
    int c2b_fd = bpf_map__fd(SKEL->maps.c2b);

    int backend1_conns_fd = bpf_map__fd(SKEL->maps.backend1_conns);
    int backend2_conns_fd = bpf_map__fd(SKEL->maps.backend2_conns);
    int backend3_conns_fd = bpf_map__fd(SKEL->maps.backend3_conns);
    int backend4_conns_fd = bpf_map__fd(SKEL->maps.backend4_conns);

    size_t buf_len = 128 * 1024;
    char buf[buf_len];

    int lfd = net_bind_tcp(&addr);
    if (lfd < 0) {
        print_err("Bind failed\n");
        exit(-1);
    }

    int epfd = epoll_create1(0);
    if (epfd < 0) {
        print_err("Failed to create epoll\n");
        exit(-1);
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN|EPOLLHUP|EPOLLRDHUP|EPOLLERR;
    ev.data.fd = lfd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, lfd, &ev) < 0) {
        print_err("Failed to add listen socket to epoll\n");
        exit(-1);
    }
    
    while (true) {
        int nfds = epoll_wait(epfd, events, MAX_EVENTS, -1);
        if (nfds == -1) {
            print_err("Failed to poll: %s\n", strerror(errno));
            exit(-1);
        }
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].events & EPOLLIN && events[i].data.fd == lfd) {
                struct sock_key client_key = { 0 };
                int cd = accept_client_conn(lfd, sockmap_fd, &client_key);
                if (cd < 0) {
                    print_err("Error accepting new connections: %s\n", strerror(errno));
                    exit(-1);
                }
                else if (cd > 0) {
                    ev.events = EPOLLIN|EPOLLHUP|EPOLLRDHUP|EPOLLERR;
                    ev.data.fd = cd;
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, cd, &ev) < 0) {
                        print_err("Failed to add client socket to epoll\n");
                        exit(-1);
                    }
                }

                continue;
            }

            struct sock_key client_key = { 0 };
            get_sock_key(events[i].data.fd, &client_key);

            if (events[i].events & EPOLLRDHUP || events[i].events & EPOLLHUP) {
                print_log("Client connection closed [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d]\n", 
                    (client_key.local_ip4 >> 24) & 0xff, (client_key.local_ip4 >> 16) & 0xff, (client_key.local_ip4 >> 8) & 0xff, client_key.local_ip4 & 0xff, client_key.local_port,
                    (client_key.remote_ip4 >> 24) & 0xff, (client_key.remote_ip4 >> 16) & 0xff, (client_key.remote_ip4 >> 8) & 0xff, client_key.remote_ip4 & 0xff, client_key.remote_port);
                
                ev.data.fd = events[i].data.fd;
                if (epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, &ev) < 0) {
                    print_err("Failed to delete client socket to epoll\n");
                    exit(-1);
                }
                close(events[i].data.fd);

                struct sock_key backend_key = { 0 };
                if (bpf_map_lookup_elem(c2b_fd, &client_key, &backend_key) < 0) {
                    print_err("bpf_lookup_elem(c2b) failed: %s\n", strerror(errno));
                    exit(-1);
                }

                // put currently assigned backend back in pool
                int conns_fd = -1;
                switch (backend_key.backend) {
                    case 1: conns_fd = backend1_conns_fd; break;
                    case 2: conns_fd = backend2_conns_fd; break;
                    case 3: conns_fd = backend3_conns_fd; break;
                    case 4: conns_fd = backend4_conns_fd; break;
                }

                if (bpf_map_update_elem(conns_fd, NULL, &backend_key, BPF_ANY) < 0) {
                    print_err("bpf_map_update_elem(backend%d_conns) failed: %s\n", backend_key.backend, strerror(errno));
                    exit(-1);
                }

                // remove the connection from the sock mappings
                if (bpf_map_delete_elem(c2b_fd, &client_key) < 0) {
                    print_err("bpf_map_delete_elem(c2b) failed: %s\n", strerror(errno));
                    exit(-1);
                }

                backend_key.backend = 0;
                if (bpf_map_delete_elem(b2c_fd, &backend_key) < 0) {
                    print_err("bpf_map_delete_elem(b2c) failed: %s\n", strerror(errno));
                    exit(-1);
                }

                continue;
            }

            if (events[i].events & EPOLLIN) {
                memset(buf, 0, buf_len);

                // read the entire request
                int con_len = -1;
                int pkt_len = -1;
                int req_len = 0;
                while (req_len < pkt_len || pkt_len < 0) {
                    ssize_t len = recv(events[i].data.fd, buf+req_len, buf_len-req_len, MSG_DONTWAIT);

                    // EAGAIN means we have to wait for eBPF verdict first
                    if (len < 0 && errno != EAGAIN) {
                        print_err("Error reading socket: %s\n", strerror(errno));
                        close(events[i].data.fd);
                        break;
                    }
                    else if (len > 0) {
                        const void* val = parse_http_hdr(buf, "Content-Length");
                        if (val != NULL) {
                            con_len = atoi(val);
                            pkt_len = con_len + parse_http_hdr_len(buf);
                        }

                        req_len += len;
                    }
                }

                // we received a new request but don't 
                // have a free connection in the pool
                int backend = parse_backend(buf);
                if (backend < 1) {
                    print_err("Invalid request: %s\n", buf);
                    continue;
                }

                // valid request -> start backend connections
                // we start all 4 connections right away, because
                // contacting userspace later is buggy
                struct sock_key backend_key = { 0 };
                int bd = -1;
                
                for (int j = 1; j < 5; j++) {
                    struct sock_key key = { 0 };
                    int fd = start_backend_conn(j, backend_addrs, sockmap_fd, &key);
                    print_log("Established a new connection to backend %d: %d\n", key.backend, fd);

                    if (add_to_sockmap(sockmap_fd, fd, &key) < 0) {
                        exit(-1);
                    }

                    if (j == backend) {
                        backend_key = key;
                        bd = fd;
                    }
                    else {
                        int conns_fd = -1;
                        switch (j) {
                            case 1: conns_fd = backend1_conns_fd; break;
                            case 2: conns_fd = backend2_conns_fd; break;
                            case 3: conns_fd = backend3_conns_fd; break;
                            case 4: conns_fd = backend4_conns_fd; break;
                        }

                        if (bpf_map_update_elem(conns_fd, NULL, &key, BPF_ANY) < 0) {
                            print_err("bpf_map_update_elem(backend%d_conns) failed: %s\n", j, strerror(errno));
                            exit(-1);
                        }
                    }
                }

                // book keeping
                if (assign_client_to_backend(c2b_fd, b2c_fd, &client_key, &backend_key) < 0) {
                    exit(-1);
                }

                if (add_to_sockmap(sockmap_fd, events[i].data.fd, &client_key) < 0) {
                    exit(-1);
                }

                size_t res_len = 0;
                do {
                    ssize_t len = write(bd, buf+res_len, req_len-res_len);
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

                // if forwarding was successful, remove POLLIN from events
                print_log("Redirected request of length %ld to backend\n", res_len);

                ev.events = POLLRDHUP|POLLHUP|POLLERR;
                ev.data.fd = events[i].data.fd;
                if (epoll_ctl(epfd, EPOLL_CTL_MOD, events[i].data.fd, &ev) < 0) {
                    print_err("Failed to modify client socket to epoll\n");
                    exit(-1);
                }
            }
        }
    }

    return NULL;
}

static void print_stats(int sig) {
    printf("Open backend connections:\n");
    for (int i = 0; i < 4; i++) {
        printf("Backend %d: %d\n", i+1, num_conn_pool[i]);
    }

    exit(0);
}

int main(int argc, char **argv) {
    signal(SIGINT, print_stats);

    int err;

    if (argc < 3) {
        print_err("Usage: %s <listen:port> <connect:port> [<connectN:portN>]\n", argv[0]);
        return -1;
    }

    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
    bump_memlock_rlimit();

    /* Open BPF application */
    SKEL = proxy_bpf__open();
    if (!SKEL) {
        print_err("Failed to open BPF skeleton\n");
        return -1;
    }

    /* Load & verify BPF programs */
    err = proxy_bpf__load(SKEL);
    if (err) {
        print_err("Failed to load and verify BPF skeleton\n");
        return -1;
    }

    cg_fd = open("/sys/fs/cgroup/", __O_DIRECTORY, O_RDONLY);
    if (cg_fd < 0) {
        print_err("failed to set reuseaddr: %s\n", strerror(errno));
        return -1;
    }

    // TODO: doing all the sock operations and connection assignments in eBPF
    // should be more efficient than doing it in userspace
    // but userspace is easier to debug
    // -> For max performance, use sockops again
    // err = bpf_prog_attach(bpf_program__fd(SKEL->progs._sock_ops), cg_fd,
    //                       BPF_CGROUP_SOCK_OPS, 0);
    // if (err < 0) {
    //     print_err("failed to attach sockops: %s\n", strerror(errno));
    //     return -1;
    // }

    sockmap_fd = bpf_map__fd(SKEL->maps.sock_map);

    err = bpf_prog_attach(bpf_program__fd(SKEL->progs.bpf_prog_parser),
                          sockmap_fd, BPF_SK_SKB_STREAM_PARSER, 0);

    if (err) {
        print_err("Failed to attach BPF parser program\n");
        return -1;
    }

    err = bpf_prog_attach(bpf_program__fd(SKEL->progs.bpf_prog_verdict),
                          sockmap_fd, BPF_SK_SKB_STREAM_VERDICT, 0);

    if (err) {
        print_err("Failed to attach BPF verdict program\n");
        return -1;
    }

    print_log("BPF programs loaded correctly!\n");

    net_parse_sockaddr(&addr, argv[1]);

    unsigned int num_backends = argc - 2;
    backend_addrs = (struct sockaddr_storage *)malloc(num_backends * sizeof(struct sockaddr_storage));
    for (int i = 0; i < num_backends; i++) {
        net_parse_sockaddr(&backend_addrs[i], argv[i + 2]);
    }

    struct url_key url_to_server[4];
    for (int i = 0; i < 4; i++) {
        bzero(url_to_server[i].url, sizeof(char) * _MAX_URL_LEN);
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
            print_err("bpf_map_update_elem(url_to_server) failed\n");
            return -1;
        }
    }

    // spawn worker threads
    pthread_t tid[NUM_WORKERS]; 
    for (int i = 0; i < NUM_WORKERS; i++) {
        if (pthread_create(&(tid[i]), NULL, &worker, NULL) < 0) {
            print_err("pthread_create failed: %s\n", strerror(errno));
            return -1;
        }
    }

    for (int i = 0; i < NUM_WORKERS; i++) {
        pthread_join(tid[i], NULL);
    }

    free(backend_addrs);
    proxy_bpf__destroy(SKEL);
    return -err;
}