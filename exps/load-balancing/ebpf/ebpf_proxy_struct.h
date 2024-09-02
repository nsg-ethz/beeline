#define _MAX_URL_SIZE 30
#define _MAX_STATUS_CODE 3

struct sock_key {
    __u32 local_ip4;
    __u32 local_port;
    __u32 remote_ip4;
    __u32 remote_port;
    __u32 backend; // [1, 4] for backend, otherwise 0
};

enum http_method {
    HTTP_NONE = 0,
    HTTP_GET = 1,
    HTTP_POST = 2,
    HTTP_HEAD = 3,
    HTTP_DELETE = 4,
    HTTP_PUT = 5,
};

struct http_hdr {
    char url[_MAX_URL_SIZE];
    __u32 url_len;

    enum http_method method;
    __u32 content_length;
    __u32 header_length;
    // char code[_MAX_STATUS_CODE];
};

struct url_key {
    char url[_MAX_URL_SIZE];
};