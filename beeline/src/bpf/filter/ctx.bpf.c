struct filter_ctx {
    u32 done_idx;

    {vars}

    char tmp[3072];
    struct addr_key dest;
};

// ---

static __always_inline struct http_match _pres_match(const struct http_parse_res *pres, u8 mid) {
    if (mid >= MAX_MATCHES) return (struct http_match){ 0 };
    return pres->ms[mid & MAX_MATCH_MASK];
}

static __always_inline int _h2_match(void *buf, bool is_skb, const struct http_parse_res *pres, u8 mid, struct bytes *str) {
    if (mid >= MAX_MATCHES) return -ENOENT;
    if (is_skb) return get_h2_match_skb(buf, pres, mid, str);
    return get_h2_match_msg(buf, pres, mid, str);
}

bpf_profile_def(ctx);
static __always_inline void _init_h1_filter_ctx(const u8 *data, const u8 *data_end, const struct sock_key *skey, struct filter_ctx *ctx, u16 done_idx, const struct http_parse_res *pres) {
    bpf_profile_start(ctx);

    u8 buf[64]; // a number cannot be larger than 64 bytes
    unsigned long tmp = 0;
    struct http_match m = {0};

    {init_h1}

    ctx->done_idx = done_idx;
    ctx->dest = (struct addr_key){ 0 };

    bpf_profile_end(ctx);
}

static __always_inline void _init_h2_filter_ctx(void *msg, bool is_skb, const struct sock_key *skey, struct filter_ctx *ctx, u16 done_idx, const struct http_parse_res *pres) {
    bpf_profile_start(ctx);

    u8 buf[64]; // a number cannot be larger than 64 bytes
    unsigned long tmp = 0;
    struct http_match m = {0};
    struct bytes str = {0};

    {init_h2}

    ctx->done_idx = done_idx;
    ctx->dest = (struct addr_key){ 0 };

    bpf_profile_end(ctx);
}
VERIFY(ctx_h1, _init_h1_filter_ctx(msg->data, msg->data_end, ikey, ctx, done_idx, pres))
VERIFY(ctx_h2, _init_h2_filter_ctx(msg, is_skb, ikey, ctx, done_idx, pres))
