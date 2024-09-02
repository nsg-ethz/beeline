#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <linux/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>

const int MAX_NUM_CONN = 1000;

void net_addr_from_name(struct sockaddr_storage *ss, const char *host) {
    struct sockaddr_in *sin = (struct sockaddr_in *)ss;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

    if (inet_pton(AF_INET, host, &sin->sin_addr) == 1) {
        sin->sin_family = AF_INET;
        return;
    }

    if (inet_pton(AF_INET6, host, &sin6->sin6_addr) == 1) {
        sin6->sin6_family = AF_INET6;
        return;
    }

    printf("inet_pton(%s)\n", host);
}

int net_bind_tcp(struct sockaddr_storage *ss) {
    int sd = socket(ss->ss_family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
    if (sd < 0) {
        printf("socket()\n");
        return -1;
    }

    int one = 1;
    int r = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&one, sizeof(one));
    if (r < 0) {
        printf("setsockopt(SO_REUSEADDR)\n");
        return -1;
    }

    r = bind(sd, (struct sockaddr *)ss, sizeof(struct sockaddr_storage));
    if (r < 0) {
        printf("bind()\n");
        return -1;
    }

    listen(sd, 1024);
    return sd;
}

int net_parse_sockaddr(struct sockaddr_storage *ss, const char *addr) {
    memset(ss, 0, sizeof(struct sockaddr_storage));

    char *colon = strrchr(addr, ':');
    if (colon == NULL || colon[1] == '\0') {
        printf("%s doesn't contain a port number.\n", addr);
        return -1;
    }

    char *endptr;
    long port = strtol(&colon[1], &endptr, 10);
    if (port < 0 || port > 65535 || *endptr != '\0') {
        printf("Invalid port number %s\n", &colon[1]);
        return -1;
    }

    char host[255];
    int addr_len = colon - addr > 254 ? 254 : colon - addr;
    strncpy(host, addr, addr_len);
    host[addr_len] = '\0';
    net_addr_from_name(ss, host);

    struct sockaddr_in *sin = (struct sockaddr_in *)ss;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;

    switch (ss->ss_family) {
    case AF_INET:
        sin->sin_port = htons(port);
        break;
    case AF_INET6:
        sin6->sin6_port = htons(port);
        break;
    default:
        printf("\n");
    }
    return -1;
}

int main(int argc, char **argv) {
    int err;

    if (argc < 2) {
        fprintf(stderr,
                "Usage: %s <listen:port>\n",
                argv[0]);
        exit(1);
    }

    struct sockaddr_storage listen;
    net_parse_sockaddr(&listen, argv[1]);

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
        printf("setsockopt(SO_KEEPALIVE)\n");
        goto cleanup;
    }

    struct sockaddr_in client_addr;
    int len = sizeof(client_addr);
    if (getpeername(fd, (struct sockaddr *)&client_addr, (socklen_t*)&len) < 0) {
        printf("Error getting peer name: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("New connection accepted: [%s:%d] socket: %d\n", inet_ntoa(client_addr.sin_addr), htons(client_addr.sin_port), fd);

    fds[num_fds].fd = fd;
    fds[num_fds].events = POLLIN|POLLHUP|POLLERR;
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
            ssize_t len = recv(fds[i].fd, buf, buf_len, 0);
            size_t req_len = strlen(buf);

            // EAGAIN means we have to wait for eBPF verdict first
            if (len < 0 && errno != EAGAIN) {
                printf("Error reading socket: %s\n", strerror(errno));
                goto cleanup;
            }
            
            // if we couldn't read yet, but also don't have an error
            // we will just try again :)
            if (len > 0) {
                printf("Received request length %ld after reading %ld: %s\n", req_len, len, buf);

                char resp[] = "HTTP/1.1 200 OK\r\n"
                  "Server: webserver-c\r\n"
                  "Content-Length: 26\r\n"
                  "Content-type: text/html\r\n\r\n"
                  "<html>hello, world</html>\r\n";
                memset(buf, 0, buf_len);
                strcpy(buf, resp);

                req_len = strlen(resp);
                size_t res_len = 0;
                do {
                    len = send(fds[i].fd, buf+res_len, req_len-res_len, 0);
                    if (len < 0) {
                        // the socket might not be ready
                        continue;
                    }
                    
                    if (len == 0) {
                        printf("message sent\n");
                        // we sent the msg
                        break;
                    }
                    printf("len: %ld\n", len);
                    res_len += len;
                } while (res_len < req_len);
                printf("Response sent\n");
            }
        }

        if (fds[i].revents & POLLHUP || fds[i].revents & POLLERR) {
            printf("Closing socket %d\n", fds[i].fd);
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
        fds[i].events = POLLIN|POLLHUP|POLLERR;
    }
    num_fds = new_num_fds;
    free(new_fds);

    // printf("Got %d open sockets\n", num_fds);
    goto accept;

cleanup:
    for (int i = 0; i < num_fds; i++) {
        close(fds[i].fd);
    }
    free(fds);

    return -err;
}