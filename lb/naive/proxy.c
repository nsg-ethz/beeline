// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Sebastiano Miano <mianosebastiano@gmail.com */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
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

#include "net.h"
#include "proxy_struct.h"
#include "hashmap.h"

#define LOG_LEVEL 2

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
const int MAX_NUM_CONN = 10000;
struct sockaddr_storage *backend_addrs;
int* bds;

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

int sock_key_compare(const struct sock_key *a, const struct sock_key *b) {
    int res = a->local_ip4 < a->local_ip4;
    if (res != 0) return res;

    res = a->local_port < b->local_port;
    if (res != 0) return res;

    res = a->remote_ip4 < b->remote_ip4;
    if (res != 0) return res;

    return a->remote_port < b->remote_port;
}

int sock_bind_compare(const void *a, const void *b, void *data) {
    struct sock_bind *asb = (struct sock_bind *)a;
    struct sock_bind *bsb = (struct sock_bind *)a;
    return sock_key_compare(&asb->key, &bsb->key);
}

uint64_t sock_bind_hash(const void *item, uint64_t seed0, uint64_t seed1) {
    struct sock_bind *bind = (struct sock_bind *)item;
    return hashmap_sip(&bind->key, sizeof(struct sock_key), seed0, seed1);
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

int start_backend_conn(int backend, struct sockaddr_storage *backend_addrss, struct sock_key* backend_key) {
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

    return fd;
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

int assign_client_to_backend(struct hashmap *c2b, struct hashmap *b2c, struct sock_key* client_key, int cd, struct sock_key* backend_key, int bd) {
    print_log("Assign client connection [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d] to [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d]\n", 
        (client_key->local_ip4 >> 24) & 0xff, (client_key->local_ip4 >> 16) & 0xff, (client_key->local_ip4 >> 8) & 0xff, client_key->local_ip4 & 0xff, client_key->local_port,
        (client_key->remote_ip4 >> 24) & 0xff, (client_key->remote_ip4 >> 16) & 0xff, (client_key->remote_ip4 >> 8) & 0xff, client_key->remote_ip4 & 0xff, client_key->remote_port,
        (backend_key->local_ip4 >> 24) & 0xff, (backend_key->local_ip4 >> 16) & 0xff, (backend_key->local_ip4 >> 8) & 0xff, backend_key->local_ip4 & 0xff, backend_key->local_port,
        (backend_key->remote_ip4 >> 24) & 0xff, (backend_key->remote_ip4 >> 16) & 0xff, (backend_key->remote_ip4 >> 8) & 0xff, backend_key->remote_ip4 & 0xff, backend_key->remote_port);

    // when retrieving a client connection given a backend connection
    // we don't know which backend was addressed, so we set backend to 0
    int backend = backend_key->backend;
    backend_key->backend = 0;
    hashmap_set(b2c, &(struct sock_bind){ .key=*backend_key, .key_fd=bd, .val=*client_key, .val_fd=cd});
    backend_key->backend = backend;

    hashmap_set(c2b, &(struct sock_bind){ .key=*client_key, .key_fd=cd, .val=*backend_key, .val_fd=bd });

    return -1*(hashmap_oom(b2c) + hashmap_oom(c2b));
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
    int num_fds = 0;
    struct pollfd *fds = (struct pollfd *)calloc(MAX_NUM_CONN, sizeof(struct pollfd));

    int num_fds_new = 0;
    struct pollfd *fds_new = (struct pollfd *)calloc(MAX_NUM_CONN, sizeof(struct pollfd));

    size_t buf_len = 64 * 1024;
    char buf[buf_len];

    struct sock_bind conn_pool[4][MAX_NUM_CONN];
    int num_conn_pool[4] = { 0 };

    struct hashmap *c2b = hashmap_new(sizeof(struct sock_bind), 0, 0, 0, sock_bind_hash, sock_bind_compare, NULL, NULL);
    struct hashmap *b2c = hashmap_new(sizeof(struct sock_bind), 0, 0, 0, sock_bind_hash, sock_bind_compare, NULL, NULL);

    int lfd = net_bind_tcp(&addr);
    if (lfd < 0) {
        print_err("Bind failed\n");
        exit(-1);
    }

    while (true) {
        if (num_fds >= MAX_NUM_CONN) {
            print_log("No new connections are accepted.\n");
            usleep(10);
            continue;
        }

        short int poll_events = POLLRDHUP|POLLHUP|POLLERR|POLLIN;
        struct sock_key client_key = { 0 };
        int cd = accept_client_conn(lfd, &client_key);
        if (cd < 0) {
            print_err("Error accepting new connections: %s\n", strerror(errno));
            exit(-1);
        }
        else if (cd > 0) {
            fds[num_fds].fd = cd;
            fds[num_fds].events = poll_events;
            num_fds++;
        }

        if (num_fds == 0) {
            usleep(10);
            continue;
        }

        // print_log("Open backend connections:\n");
        // for (int i = 0; i < 4; i++) {
        //     print_log("backend %d: %d\n", i+1, num_conn_pool[i]);
        // }

        int nfds = poll(fds, num_fds, 10);
        if (nfds == -1) {
            print_err("Failed to poll: %s\n", strerror(errno));
            exit(-1);
        }
        else if (nfds == 0) {
            continue;
        }

        memset(fds_new, 0, MAX_NUM_CONN*sizeof(struct pollfd));
        num_fds_new = 0;

        for (int i = 0; i < num_fds; i++) {
            struct sock_key fd_key = { 0 };
            get_sock_key(fds[i].fd, &fd_key);

            if (fds[i].revents & POLLRDHUP || fds[i].revents & POLLHUP) {
                print_log("Client connection closed [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d]\n", 
                    (fd_key.local_ip4 >> 24) & 0xff, (fd_key.local_ip4 >> 16) & 0xff, (fd_key.local_ip4 >> 8) & 0xff, fd_key.local_ip4 & 0xff, fd_key.local_port,
                    (fd_key.remote_ip4 >> 24) & 0xff, (fd_key.remote_ip4 >> 16) & 0xff, (fd_key.remote_ip4 >> 8) & 0xff, fd_key.remote_ip4 & 0xff, fd_key.remote_port);
                close(fds[i].fd);

                struct sock_bind *bind = (struct sock_bind *)hashmap_get(c2b, &(struct sock_bind){ .key=fd_key });
                if (bind == NULL) {
                    print_err("Failed to find client connection\n");
                    exit(-1);
                }

                // put backend connection back into the pool
                int backend = bind->val.backend;
                memcpy(&conn_pool[backend-1][num_conn_pool[backend-1]], bind, sizeof(struct sock_bind));
                num_conn_pool[backend-1]++;

                // remove client - backend binding
                bind->val.backend = 0;
                if (hashmap_delete(b2c, &(struct sock_bind){ .key=bind->val }) == NULL) {
                    print_err("Failed to delete b2c binding\n");
                    exit(-1);
                }
                if (hashmap_delete(c2b, &(struct sock_bind){ .key=bind->key }) == NULL) {
                    print_err("Failed to delete c2b binding\n");
                    exit(-1);
                }

                continue;
            }
            else {
                fds_new[num_fds_new].fd = fds[i].fd;
                fds_new[num_fds_new].events = fds[i].events;
                num_fds_new++;
            }

            if (fds[i].revents & POLLIN) {
                memset(buf, 0, buf_len);

                // read the entire request
                int req_len = read_req(fds[i].fd, buf, buf_len);
                print_log("Read request of length: %d\n", req_len);

                // check if this comes from a backend
                struct sock_bind *bind = (struct sock_bind *)hashmap_get(b2c, &(struct sock_bind){ .key=fd_key });
                int fd = -1;
                if (bind != NULL) {
                    print_log("Received response from backend: %d\n", fds[i].fd);
                    fd = bind->val_fd;
                }
                else {
                    // we received a client request
                    // check which backend is requested
                    int backend = parse_backend(buf);
                    if (backend < 1) {
                        print_err("Invalid request: %s\n", buf);
                        exit(-1);
                    }

                    print_log("Received request from client %d to backend %d\n", fds[i].fd, backend);

                    // check if this is an exisiting connection
                    bind = (struct sock_bind *)hashmap_get(c2b, &(struct sock_bind){ .key=fd_key });
                    if (bind != NULL) {                    
                        struct sock_key backend_key = bind->val;
                        if (backend_key.backend == backend) {
                            // request to the same backend
                            fd = bind->val_fd;
                            print_log("Request to the same backend: %d\n", backend);
                        }
                        else {
                            // put backend connection back into the pool
                            int old_backend = bind->val.backend;
                            memcpy(&conn_pool[old_backend-1][num_conn_pool[old_backend-1]], bind, sizeof(struct sock_bind));
                            num_conn_pool[old_backend-1]++;

                            // remove client - backend binding
                            bind->val.backend = 0;
                            if (hashmap_delete(b2c, &(struct sock_bind){ .key=bind->val }) == NULL) {
                                print_err("Failed to delete b2c binding\n");
                                exit(-1);
                            }
                            if (hashmap_delete(c2b, &(struct sock_bind){ .key=bind->key }) == NULL) {
                                print_err("Failed to delete c2b binding\n");
                                exit(-1);
                            }

                            // check if we have an open connection to the current backend
                            if (num_conn_pool[backend-1] > 0) {
                                bind = &conn_pool[backend-1][num_conn_pool[backend-1]-1];
                                num_conn_pool[backend-1]--;
                                fd = bind->val_fd;
                                if (assign_client_to_backend(c2b, b2c, &fd_key, fds[i].fd, &bind->val, bind->val_fd) < 0) {
                                    print_err("Failed to assign client to backend\n");
                                    exit(-1);
                                }
                                print_log("Reusing backend connection: %d\n", bind->val_fd);
                            }
                            else {
                                // start a new connection
                                fd = start_backend_conn(backend, backend_addrs, &backend_key);
                                print_log("Established a new connection to backend %d: %d\n", backend, fd);
                                if (assign_client_to_backend(c2b, b2c, &fd_key, fds[i].fd, &backend_key, fd) < 0) {
                                    print_err("Failed to assign client to backend\n");
                                    exit(-1);
                                }

                                fds_new[num_fds_new].fd = fd;
                                fds_new[num_fds_new].events = poll_events;
                                num_fds_new++;
                                
                                if (num_fds_new >= MAX_NUM_CONN) {
                                    print_err("Too many connections\n");
                                    exit(-1);
                                }
                            }
                        }
                    }
                    else {
                        print_log("New connection to backend %d\n", backend);
                        struct sock_key backend_key;
                        fd = start_backend_conn(backend, backend_addrs, &backend_key);
                        print_log("Established a new connection to backend %d: %d\n", backend, fd);
                        assign_client_to_backend(c2b, b2c, &fd_key, fds[i].fd, &backend_key, fd);

                        fds_new[num_fds_new].fd = fd;
                        fds_new[num_fds_new].events = poll_events;
                        num_fds_new++;

                        if (num_fds_new >= MAX_NUM_CONN) {
                            print_err("Too many connections\n");
                            exit(-1);
                        }
                    }
                }

                assert(fd > 0);

                print_log("Forwarding request to socket %d\n", fd);
                write_req(fd, buf, req_len);
            }
        }

        num_fds = num_fds_new;
        memcpy(fds, fds_new, MAX_NUM_CONN*sizeof(struct pollfd));
    }

    close(lfd);
    free(fds);
    free(fds_new);
    hashmap_free(c2b);
    hashmap_free(b2c);
    return NULL;
}

int main(int argc, char **argv) {
    int err;

    if (argc < 3) {
        print_err("Usage: %s <listen:port> <connect:port> [<connectN:portN>]\n", argv[0]);
        return -1;
    }

    net_parse_sockaddr(&addr, argv[1]);

    unsigned int num_backends = argc - 2;
    backend_addrs = (struct sockaddr_storage *)malloc(num_backends * sizeof(struct sockaddr_storage));
    for (int i = 0; i < num_backends; i++) {
        net_parse_sockaddr(&backend_addrs[i], argv[i + 2]);
    }

    // spawn two threads, one that waits for new conections
    // and one that forwards requests
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

    // clean up
    free(backend_addrs);
    free(bds);
    return -err;
}