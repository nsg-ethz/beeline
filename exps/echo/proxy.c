// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Sebastiano Miano <mianosebastiano@gmail.com */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "net.h"
#include "proxy_struct.h"

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

int sockmap_fd;
struct sockaddr_storage addr;

const int NUM_WORKERS = 1;
const int MAX_NUM_CONN = 1000;
const int MAX_EVENTS = 1000;

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

int accept_client_conn(int lfd, struct sock_key* client_key) {
    struct sockaddr_storage client;
    socklen_t client_len = sizeof(struct sockaddr_storage);
    int fd = accept(lfd, (struct sockaddr *)&client, &client_len);

    if (fd < 0) {
        if (errno != EAGAIN) {
            print_err("Error accepting new connection.");
            return -1;
        }
        return 0;
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

int parse_http_hdr_len(const char* hdr) {
    const char *sep = "\r\n\r\n";
    char *next = strstr(hdr, sep);
    if (next != NULL) {
        return next-hdr;
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

int read_req(int fd, char *buf, size_t buf_len) {
    int req_len = 0;
    int con_len = 0;
    int seg_len = 0;
    ssize_t len = 0;

    do {
        const void* val = parse_http_hdr(buf, "Content-Length");
        if (val != NULL) {
            con_len = atoi(val);
            seg_len = con_len + parse_http_hdr_len(buf);
        }

        if (len > 0) req_len += len;
        len = recv(fd, buf+req_len, buf_len-req_len, MSG_DONTWAIT);
    } while ((seg_len == 0 || req_len < seg_len) && len != 0);

    return req_len;
}

int write_req(int fd, char *buf, size_t req_len) {
    size_t res_len = 0;
    do {
        ssize_t len = write(fd, buf+res_len, req_len-res_len);
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

    return res_len;
}

void* worker(void* arg) {
    size_t buf_len = 64 * 1024;
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
                int cd = accept_client_conn(lfd, &client_key);
                if (cd < 0) {
                    print_err("Error accepting new connections: %s\n", strerror(errno));
                    exit(-1);
                }
                else if (cd > 0) {
                    ev.data.fd = cd;
                    if (epoll_ctl(epfd, EPOLL_CTL_ADD, cd, &ev) < 0) {
                        print_err("Failed to add client socket to epoll\n");
                        exit(-1);
                    }
                }

                continue;
            }

            struct sock_key fd_key = { 0 };
            get_sock_key(events[i].data.fd, &fd_key);

            if (events[i].events & EPOLLRDHUP || events[i].events & EPOLLHUP) {
                print_log("Client connection closed [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d]\n", 
                    (fd_key.local_ip4 >> 24) & 0xff, (fd_key.local_ip4 >> 16) & 0xff, (fd_key.local_ip4 >> 8) & 0xff, fd_key.local_ip4 & 0xff, fd_key.local_port,
                    (fd_key.remote_ip4 >> 24) & 0xff, (fd_key.remote_ip4 >> 16) & 0xff, (fd_key.remote_ip4 >> 8) & 0xff, fd_key.remote_ip4 & 0xff, fd_key.remote_port);

                ev.data.fd = events[i].data.fd;
                if (epoll_ctl(epfd, EPOLL_CTL_DEL, events[i].data.fd, &ev) < 0) {
                    print_err("Failed to delete client socket to epoll\n");
                    exit(-1);
                }
                close(events[i].data.fd);

                continue;
            }

            if (events[i].events & EPOLLIN) {
                memset(buf, 0, buf_len);

                // read the entire request
                int req_len = read_req(events[i].data.fd, buf, buf_len);
                print_log("Read request of length: %d\n", req_len);

                print_log("Forwarding request to socket %d\n", fd);
                write_req(events[i].data.fd, buf, req_len);
            }
        }
    }

    close(lfd);
    return NULL;
}

int main(int argc, char **argv) {
    int err;

    if (argc < 2) {
        print_err("Usage: %s <listen:port>\n", argv[0]);
        return -1;
    }

    net_parse_sockaddr(&addr, argv[1]);

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

    return -err;
}