static __always_inline int _parse_http_method(const char *data, const char *data_end, struct http_hdr *http) {
    if (data + 6 > data_end) return -1;

    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T') {
        http->method = HTTP_GET;
    }
    else if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') {
        http->method = HTTP_POST;
    }
    else if ((data[0] == 'P') && (data[1] == 'U') && (data[2] == 'T')) {
        http->method = HTTP_PUT;
    }
    else if ((data[0] == 'D') && (data[1] == 'E') && (data[2] == 'L') &&
        (data[3] == 'E') && (data[4] == 'T') && (data[5] == 'E')) {
        http->method = HTTP_DELETE;
    }
    else if ((data[0] == 'H') && (data[1] == 'E') && (data[2] == 'A') &&
        (data[3] == 'D')) {
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

static __always_inline int _parse_http_req_url(const char *line, const char *line_end, struct http_hdr *hdr) {
    if (hdr->method == HTTP_NONE) return 0;

    __u32 method_len = _get_method_len(hdr->method);
    __u32 data_len = line_end - line;
    __u32 line_len = data_len - method_len - 1;

    hdr->url_len = 0;
    for (__u32 i = 0; i < _MAX_URL_SIZE && i < line_len; i++) {
        char c = line[i + method_len + 1];
        if (c == ' ') break;

        hdr->url[i] = c;
        hdr->url_len++;
    }
    
    return 0;
}

static __always_inline int _parse_content_length(const char *data, const char *data_end, struct http_hdr *hdr) {
    if (data + 15 > data_end) return -1;

    bpf_printk("LINE: %s", data);

    if (data[0] == 'C' && data[1] == 'o' && data[2] == 'n' &&
        data[3] == 't' && data[4] == 'e' && data[5] == 'n' &&
        data[6] == 't' && data[7] == '-' && data[8] == 'L' &&
        data[9] == 'e' && data[10] == 'n' && data[11] == 'g' &&
        data[12] == 't' && data[13] == 'h' && data[14] == ':') {
            char *start = (char*)((__u64)data + 15);
            __u32 len = data_end-data-15;
            char buf[20];
            if (bpf_probe_read_kernel_str(buf, 20, start) < 0) {
                bpf_printk("failed reading");
            }
        return bpf_strtoul(start, len, 0, (unsigned long*)&hdr->content_length);
    }

    return -1;
}

static __always_inline int _parse_http_hdr_line(const char *line, const char *line_end, struct http_hdr *hdr) {
    if (_parse_http_method(line, line_end, hdr) == 0) {
        return _parse_http_req_url(line, line_end, hdr);
    }
    // else if (_parse_content_length(line, line_end, hdr) == 0) {
    //     return 0;
    // }
    
    return -1; 
}
