struct filter_ctx {
    u32 done_idx;

    {vars}

    char tmp[3072];
    struct addr_key dest;
};

// ---

bpf_profile_def(ctx);
static __always_inline void _init_h1_filter_ctx(const char *data, const char *data_end, const struct sock_key *skey, struct filter_ctx *ctx, u16 done_idx, const struct parse_res *pres) {
    bpf_profile_start(ctx);

    char buf[64]; // a number cannot be larger than 64 bytes
    unsigned long tmp = 0;
    struct hdr_match m = {0};

    {init_h1}

    ctx->done_idx = done_idx;
    ctx->dest = (struct addr_key){ 0 };

    bpf_profile_end(ctx);
}

static __always_inline void _init_h2_filter_ctx(const char *data, const char *data_end, const struct sock_key *skey, struct filter_ctx *ctx, u16 done_idx, const struct parse_res *pres) {
    bpf_profile_start(ctx);

    char buf[64]; // a number cannot be larger than 64 bytes
    unsigned long tmp = 0;
    struct hdr_match m = {0};
    u8 *ptr = NULL;

    {init_h2}

    ctx->done_idx = done_idx;
    ctx->dest = (struct addr_key){ 0 };

    bpf_profile_end(ctx);
}
