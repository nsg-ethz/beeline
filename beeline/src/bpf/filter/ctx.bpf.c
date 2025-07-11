struct pipeline_ctx {
    u32 done_idx;

    {vars}

    char tmp[2048];
    struct addr_key dest;
};

// ---

static __always_inline void _init_pipeline_ctx(struct sk_msg_md *msg, struct pipeline_ctx *ctx, u16 done_idx, const struct prange *pranges) {
    char *data = (char *)(long)msg->data;
    char buf[64]; // a number cannot be larger than 64 bytes
    unsigned long tmp = 0;
    struct prange r = {0};

    {init}

    ctx->done_idx = done_idx;
    ctx->dest = (struct addr_key){ 0 };
}
