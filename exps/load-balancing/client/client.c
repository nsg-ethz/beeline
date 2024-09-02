#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>

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

int net_connect_tcp_blocking(struct sockaddr_storage *ss, int do_zerocopy) {
    int sd = socket(ss->ss_family, SOCK_STREAM, IPPROTO_TCP);
    if (sd < 0) {
        printf("socket()\n");
        return -1;
    }

    /* Don't buffer partial packets */
    int one = 1;
    int r = setsockopt(sd, SOL_TCP, TCP_NODELAY, &one, sizeof(one));
    if (r < 0) {
        printf("setsockopt()\n");
        return -1;
    }

    /* Cubic is a bit more stable in tests than bbr */
    char *cong = "cubic";
    r = setsockopt(sd, SOL_TCP, TCP_CONGESTION, cong, strlen(cong));
    if (r < 0) {
        printf("setsockopt(TCP_CONGESTION)\n");
        return -1;
    }

    if (do_zerocopy) {
        /* Zerocopy shall be set on the parent accept socket. */
        one = 1;
        r = setsockopt(sd, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof(one));
        if (r < 0) {
            printf("getsockopt()\n");
            return -1;
        }
    }

again:;
    r = connect(sd, (struct sockaddr *)ss, sizeof(struct sockaddr_storage));
    if (r < 0) {
        if (errno == EINTR) {
            goto again;
        }
        printf("connect()\n");
        return -1;
    }

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
                "Usage: %s <url:port>\n",
                argv[0]);
        exit(1);
    }

    struct sockaddr_storage addr;
    net_parse_sockaddr(&addr, argv[1]);

    int sd = net_connect_tcp_blocking(&addr, 0);

    char req[] = "GET /server1 HTTP/1.1\r\n"
                 "Host: 127.0.0.1:8000\r\n"
                 "User-Agent: client\r\n\r\n";
    char res[] = "HTTP/1.1 200 OK";

    size_t req_len = strlen(req);
    size_t res_len = strlen(res);

    for (int i = 0;; i++) {
        printf("send req...\n");
        size_t sent = 0;    
        do {
            ssize_t len = send(sd, req+sent, req_len-sent, 0);
            if (len < 0) {
                printf("Error writing socket: %s\n", strerror(errno));
                // the socket might not be ready
                continue;
            }
            
            sent += len;
        } while (sent < req_len);

        size_t buf_len = 1024;
        char buf[buf_len];
        memset(buf, 0, buf_len);

        // read the entire request
        printf("waiting for res...\n");
        size_t recv = 0;
        do {
            ssize_t len = read(sd, buf, buf_len);
            if (len < 0) {
                printf("Error reading socket: %s\n", strerror(errno));
                exit(-1);
            }

            recv += len;
        } while (recv < res_len);

        printf("Received response (%d):%s\n", i, buf);

        assert(strlen(buf) > res_len);
        assert(strstr(buf, res) != NULL);

        // usleep(50000);
        sleep(1);
    }
}