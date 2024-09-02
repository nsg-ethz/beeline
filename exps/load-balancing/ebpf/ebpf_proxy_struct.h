#define _MAX_URL_SIZE 30
#define _MAX_STATUS_CODE 3

struct sock_key {
    __u32 ip4;
    __u32 port;
    __u32 backend; // 1-4 for backend, 0 for client
};

enum http_event_state {
    HTTP_GET = 0,
    HTTP_POST = 1,
    HTTP_HEAD = 2,
    HTTP_DELETE = 3,
    HTTP_PUT = 4,
    HTTP_RESPONSE = 5,
    NO_HTTP_PACKET = 6,
};

struct http_state {
    char url[_MAX_URL_SIZE];
    char code[_MAX_STATUS_CODE];
    enum http_event_state state;
    uint32_t url_size;
};

struct url_value {
    char url[_MAX_URL_SIZE];
};