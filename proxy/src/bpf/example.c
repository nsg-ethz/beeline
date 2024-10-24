struct ds_conn_state {
    __u32 num_bytes;
    __u32 num_reqs;
    __u64 last_req_ts;
    __u64 this_req_ts;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct sock_key);
    __type(value, struct ds_conn_state);
} ds_conns SEC(".maps");

struct us_conn_state {
    __u32 num_bytes;
    __u32 num_reqs;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct addr_key);
    __type(value, struct us_conn_state);
} us_conns SEC(".maps");

struct parse_res {
    __u32 content_length;
    bool backend_is_server1;
    bool backend_is_server2;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, sock_key);
    __type(value, __u32);
} us2ds_routes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100);
    __type(key, __u32);
    __type(value, __u32);
} ds2us_routes SEC(".maps");

// int buf_len = sizeof(params->content_length);
//     long content_length = 0;
//     bpf_strtoul(params->content_length, buf_len, 10, &content_length);

int update_ds_state(struct sock_key *dkey, struct parse_res *params) {
    struct ds_conn_state *state = bpf_map_lookup_elem(&ds_conns, dkey);
    if (state == NULL) {
        struct ds_conn_state new_state = {
            .num_bytes = params->content_length,
            .num_reqs = 1,
            .last_req_ts = 0,
            .this_req_ts = bpf_ktime_get_ns()
        };
        bpf_map_update_elem(&ds_conns, dkey, &new_state, BPF_ANY);
    }
    else {
        state->num_bytes += params->content_length;
        state->num_reqs++;
        state->last_req_ts = state->this_req_ts;
        state->this_req_ts = bpf_ktime_get_ns();
    }

    return 0;
}

int route_upstream(struct sock_key *dkey, struct ds_conn_state *state, struct parse_res *params, int *us_sock_id) {
    // rate limit connection if it's sent a request less than 1ms ago
    __u64 req_interval = state->this_req_ts - state->last_req_ts;
    if (state->last_req_ts < 10000000) {
        return PR_DROP;
    }

    if (params->backend_is_server1) {
        int key = 0;
        us_sock_id = bpf_map_lookup_elem(&ds2us_routes, &key);
        return PR_PASS;
    }
    if (params->backend_is_server2) {
        int key = 1;
        us_sock_id = bpf_map_lookup_elem(&ds2us_routes, &key);
        return PR_PASS;
    }
    
    return PR_USPA;
}

int route_downstream(struct sock_key *ukey, struct us_conn_state *state, struct parse_res *params, int *ds_sock_id) {
    ds_sock_id = bpf_map_lookup_elem(&ds2us_routes, ukey);
    return PR_PASS;
}

int update_us_state(struct sock_key *ukey, struct parse_res *params) {
    struct addr_key *rukey = ukey->remote;
    struct us_conn_state *state = bpf_map_lookup_elem(&us_conns, rukey);
    if (state == NULL) {
        struct us_conn_state new_state = {
            .num_bytes = params->content_length,
            .num_reqs = 1,
        };
        bpf_map_update_elem(&ds_conns, rukey, &new_state, BPF_ANY);
    }
    else {
        state->num_bytes += params->content_length;
        state->num_reqs++;
    }

    return PR_PASS;
}