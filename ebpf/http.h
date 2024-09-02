static __always_inline int _parse_http_method(const char *line, __u32 len, struct http_hdr *http) {
    if (len < 6) return -1;

    if (line[0] == 'G' && line[1] == 'E' && line[2] == 'T') {
        http->method = HTTP_GET;
    }
    else if (line[0] == 'P' && line[1] == 'O' && line[2] == 'S' && line[3] == 'T') {
        http->method = HTTP_POST;
    }
    else if ((line[0] == 'P') && (line[1] == 'U') && (line[2] == 'T')) {
        http->method = HTTP_PUT;
    }
    else if ((line[0] == 'D') && (line[1] == 'E') && (line[2] == 'L') &&
        (line[3] == 'E') && (line[4] == 'T') && (line[5] == 'E')) {
        http->method = HTTP_DELETE;
    }
    else if ((line[0] == 'H') && (line[1] == 'E') && (line[2] == 'A') &&
        (line[3] == 'D')) {
        http->method = HTTP_HEAD;
    }
    else {
        return -1;
    }

    return 0;
}

static __always_inline __u32 _get_method_len(enum http_method method) {
    switch (method) {
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
}

static __always_inline int _parse_http_req_url(const char *line, __u32 len, struct http_hdr *hdr) {
    if (hdr->method == HTTP_NONE) return 0;

    __u32 method_len = _get_method_len(hdr->method);
    __s32 url_len = len - method_len - 1 - 9; // 9 is the length of " HTTP/1.1"
    if (url_len <= 0 || url_len > _MAX_URL_LEN) return -1;

    if (bpf_probe_read_kernel(hdr->url, url_len, line + method_len + 1) < 0) {
        return -1;
    }

    hdr->url_len = url_len;
    return 0;
}

static __always_inline int _parse_content_length(const char *line, __u32 len, struct http_hdr *hdr) {
    const char* key = "Content-Length:";
    __u32 key_len = 15;

    if (len < key_len) return -1;
    if (bpf_strncmp(line, key_len, key) < 0) return -1;

    return bpf_strtoul(line + key_len, 10, 0, (unsigned long*)&hdr->content_length);
}

static __always_inline int _parse_http_hdr_line(const char *line, __u32 len, struct http_hdr *hdr) {
    if (_parse_http_method(line, len, hdr) >= 0) {
        return _parse_http_req_url(line, len, hdr);
    }
    else if (_parse_content_length(line, len, hdr) >= 0) {
        return 0;
    }
    
    return -1; 
}
