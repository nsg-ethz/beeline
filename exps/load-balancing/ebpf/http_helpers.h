static __always_inline bool is_http_request(const char *buf,
                                            struct http_state *http) {
    if (buf[0] == 'G' && buf[1] == 'E' && buf[2] == 'T') {
        http->state = HTTP_GET;
        return true;
    }
    if (buf[0] == 'P' && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T') {
        http->state = HTTP_POST;
        return true;
    }
    if ((buf[0] == 'P') && (buf[1] == 'U') && (buf[2] == 'T')) {
        http->state = HTTP_PUT;
        return true;
    }
    if ((buf[0] == 'D') && (buf[1] == 'E') && (buf[2] == 'L') &&
        (buf[3] == 'E') && (buf[4] == 'T') && (buf[5] == 'E')) {
        http->state = HTTP_DELETE;
        return true;
    }
    if ((buf[0] == 'H') && (buf[1] == 'E') && (buf[2] == 'A') &&
        (buf[3] == 'D')) {
        http->state = HTTP_HEAD;
        return true;
    }

    return false;
}

static __always_inline uint32_t get_method_len(enum http_event_state state) {
    switch (state) {
    case HTTP_GET:
    case HTTP_PUT:
        return 3;
    case HTTP_POST:
    case HTTP_HEAD:
        return 4;
    case HTTP_DELETE:
        return 6;
    default:
        return 0;
    }

    return 0;
}

static __always_inline char get_url_from_request(const char *buf,
                                                 uint32_t start_off,
                                                 uint32_t end,
                                                 enum http_event_state state,
                                                 struct url_value *url) {
    bool found_cr = false;

    uint32_t http_url_len = 0;
    uint32_t i = 0;
    for (i = start_off; i < end; i++) {
        if (buf[i] == '\r')
            found_cr = true;

        if (buf[i] == '\n' && found_cr) {
            http_url_len = i - 14;
            break;
        }
    }

    http_url_len = i - 11 - get_method_len(state);
    char last_c = '1';

    if (http_url_len > 0) {
        for (uint16_t k = 0; k < _MAX_URL_SIZE; k++) {
            if (k < http_url_len) {
                url->url[k] = buf[k + start_off];
                last_c = buf[k + start_off];
            }
        }
    }
    // http->url_size = http_url_len;

    return last_c;
}

static __always_inline bool is_http_response(const char *buf,
                                             struct http_state *http) {
    if (buf[0] == 'H' && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
        http->state = HTTP_RESPONSE;
        return true;
    }

    return false;
}