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
#include <liburing.h>

#include "net.h"
#include "proxy_struct.h"
#include "hashmap.h"

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
struct io_uring ring;
struct sockaddr_storage *backend_addrs;
int num_conn_pool[4] = { 0 };

#define EVENT_TYPE_ACCEPT       0
#define EVENT_TYPE_READ         1
#define EVENT_TYPE_WRITE        2

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
    int res = a->local_ip4 < b->local_ip4;
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

int add_accept_request(struct io_uring *ring, int fd, struct sockaddr *client_addr, socklen_t *client_addr_len) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    struct request *req = malloc(sizeof(struct request));
    req->event_type = EVENT_TYPE_ACCEPT;

    io_uring_prep_accept(sqe, fd, client_addr, client_addr_len, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(ring);

    return 0;
}

int add_read_request(struct io_uring* ring, int fd, struct sock_key* key) {
    int len = 32 * 1024;
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    struct request *req = malloc(sizeof(struct request));
    memcpy(&req->key, key, sizeof(struct sock_key));
    req->fd = fd;
    req->event_type = EVENT_TYPE_READ;
    req->buf = calloc(len, sizeof(char));

    io_uring_prep_recv(sqe, fd, req->buf, len, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(ring);
    return 0;
}

int add_write_request(struct io_uring* ring, int fd, char *buf, int len, struct sock_key* key) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    struct request *req = malloc(sizeof(struct request));
    memcpy(&req->key, key, sizeof(struct sock_key));
    req->fd = fd;
    req->event_type = EVENT_TYPE_WRITE;
    req->buf = buf;

    io_uring_prep_send(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(ring);
    return 0;
}

int assign_client_to_backend(struct hashmap *c2b, struct hashmap *b2c, struct sock_key* client_key, int cd, struct sock_key* backend_key, int bd) {
    print_log("Assign client connection [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d] to [%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d]\n", 
        (client_key->local_ip4 >> 24) & 0xff, (client_key->local_ip4 >> 16) & 0xff, (client_key->local_ip4 >> 8) & 0xff, client_key->local_ip4 & 0xff, client_key->local_port,
        (client_key->remote_ip4 >> 24) & 0xff, (client_key->remote_ip4 >> 16) & 0xff, (client_key->remote_ip4 >> 8) & 0xff, client_key->remote_ip4 & 0xff, client_key->remote_port,
        (backend_key->local_ip4 >> 24) & 0xff, (backend_key->local_ip4 >> 16) & 0xff, (backend_key->local_ip4 >> 8) & 0xff, backend_key->local_ip4 & 0xff, backend_key->local_port,
        (backend_key->remote_ip4 >> 24) & 0xff, (backend_key->remote_ip4 >> 16) & 0xff, (backend_key->remote_ip4 >> 8) & 0xff, backend_key->remote_ip4 & 0xff, backend_key->remote_port);

    hashmap_set(b2c, &(struct sock_bind){ .key=*backend_key, .key_fd=bd, .val=*client_key, .val_fd=cd});
    hashmap_set(c2b, &(struct sock_bind){ .key=*client_key, .key_fd=cd, .val=*backend_key, .val_fd=bd });

    return -1*(hashmap_oom(b2c) + hashmap_oom(c2b));
}

void* worker(void* arg) {
    struct sock_bind conn_pool[4][MAX_NUM_CONN];

	if (io_uring_queue_init(256, &ring, 0) < 0) {
		print_err("io_uring_queue_init error: %s\n", strerror(errno));
        exit(-1);
	}

    int lfd = net_bind_tcp(&addr);
    if (lfd < 0) {
        print_err("Bind failed\n");
        exit(-1);
    }

    socklen_t addr_len = sizeof(addr);
    add_accept_request(&ring, lfd, (struct sockaddr*)&addr, &addr_len);

    struct hashmap *c2b = hashmap_new(sizeof(struct sock_bind), 0, 0, 0, sock_bind_hash, sock_bind_compare, NULL, NULL);
    struct hashmap *b2c = hashmap_new(sizeof(struct sock_bind), 0, 0, 0, sock_bind_hash, sock_bind_compare, NULL, NULL);

    struct io_uring_cqe *cqe;
    while (true) {
        if (io_uring_wait_cqe(&ring, &cqe) < 0) {
            print_err("io_uring_wait_cqe error: %s\n", strerror(errno));
            exit(-1);
        }

        struct request *req = (struct request *)cqe->user_data;
        if (cqe->res < 0) {
            print_err("Async request failed: %s for socket: %d, event: %d\n", strerror(-cqe->res), req->fd, req->event_type);
        }

        switch (req->event_type) {
            case EVENT_TYPE_ACCEPT: {
                int cd = cqe->res;
                struct sock_key key = { 0 };
                get_sock_key(cd, &key);

                add_accept_request(&ring, lfd, (struct sockaddr*)&addr, &addr_len);
                add_read_request(&ring, cd, &key);
                print_log("Accepted new client connection: %d\n", cd);
                break;
            }
            case EVENT_TYPE_READ: {
                struct sock_key key = req->key;

                // check if there is something to read
                if (cqe->res == 0) {
                    print_log("Closing socket: %d\n", req->fd);
                    close(req->fd);
                    break;
                }

                // check if this is a backend response
                if (key.backend > 0) {
                    print_log("Received response from backend: %d\n", key.backend);

                    // read from the backend
                    add_read_request(&ring, req->fd, &key);

                    struct sock_bind *bind = (struct sock_bind *)hashmap_get(b2c, &(struct sock_bind){ .key=key });
                    if (bind == NULL) {
                        print_err("Failed to find client associated to backend: %d\n", req->fd);
                        exit(-1);
                    }

                    // write to the client
                    add_write_request(&ring, bind->val_fd, req->buf, cqe->res, &bind->val);   
                    break;
                }

                struct sock_bind *bind = (struct sock_bind *)hashmap_get(c2b, &(struct sock_bind){ .key=key });

                // we received a client request
                // check which backend is requested
                int backend = parse_backend(req->buf);
                if (backend < 1) {
                    // it's possible that the request got split up into multiple segments
                    // because the payload is so large
                    // in that case, we should already have a backend assigned
                    if (bind == NULL) {
                        print_err("Received partial request of len %d from client %d without backend\n", cqe->res, req->fd);
                        break;
                    }

                    backend = bind->val.backend;
                }

                assert(backend > 0);

                print_log("Received request of len %d from client %d to backend %d\n", cqe->res, req->fd, backend);
                int fd = -1;
                struct sock_key backend_key;

                // check if this is an exisiting connection
                if (bind != NULL) {                    
                    if (bind->val.backend == backend) {
                        // request to the same backend
                        print_log("Request to the same backend: %d\n", backend);
                        fd = bind->val_fd;
                        backend_key = bind->val;
                    }
                    else {
                        // put backend connection back into the pool
                        int old_backend = bind->val.backend;
                        assert(old_backend > 0);
                        memcpy(&conn_pool[old_backend-1][num_conn_pool[old_backend-1]], bind, sizeof(struct sock_bind));
                        num_conn_pool[old_backend-1]++;

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
                            struct sock_bind reuse_bind = conn_pool[backend-1][num_conn_pool[backend-1]-1];
                            num_conn_pool[backend-1]--;

                            fd = reuse_bind.val_fd;
                            backend_key = reuse_bind.val;
                            if (assign_client_to_backend(c2b, b2c, &key, req->fd, &backend_key, fd) < 0) {
                                print_err("Failed to assign client to backend\n");
                                exit(-1);
                            }
                            
                            print_log("Reusing backend connection: %d\n", fd);
                        }
                        else {
                            // start a new connection
                            fd = start_backend_conn(backend, backend_addrs, &backend_key);
                            print_log("Established a new connection to backend %d: %d\n", backend, fd);
                            if (assign_client_to_backend(c2b, b2c, &key, req->fd, &backend_key, fd)) {
                                print_err("Failed to assign client to backend\n");
                                exit(-1);
                            }
                        }
                    }
                }
                else {
                    print_log("New connection to backend %d\n", backend);
                    fd = start_backend_conn(backend, backend_addrs, &backend_key);
                    print_log("Established a new connection to backend %d: %d\n", backend, fd);
                    if (assign_client_to_backend(c2b, b2c, &key, req->fd, &backend_key, fd)) {
                        print_err("Failed to assign client to backend\n");
                        exit(-1);
                    }
                }

                assert(fd > 0);

                // read from the client again
                add_read_request(&ring, req->fd, &key);

                // read from the backend
                add_read_request(&ring, fd, &backend_key);

                // write to the backend
                add_write_request(&ring, fd, req->buf, cqe->res, &backend_key);   

                break;
            }
            case EVENT_TYPE_WRITE: {
                print_log("Sent response of length: %d\n", cqe->res);
                free(req->buf);

                break;
            }
        }

        free(req);

        /* Mark this request as processed */
        io_uring_cqe_seen(&ring, cqe);
    }

    io_uring_queue_exit(&ring);
    close(lfd);
    return NULL;
}

static void print_stats(int sig) {
    io_uring_queue_exit(&ring);
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

    net_parse_sockaddr(&addr, argv[1]);

    unsigned int num_backends = argc - 2;
    backend_addrs = (struct sockaddr_storage *)malloc(num_backends * sizeof(struct sockaddr_storage));
    for (int i = 0; i < num_backends; i++) {
        net_parse_sockaddr(&backend_addrs[i], argv[i + 2]);
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

    // clean up
    free(backend_addrs);
    return -err;
}