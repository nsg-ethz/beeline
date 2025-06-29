struct pipeline_ctx {
    u32 done_idx;

    {ranges}
    {vars}

    char tmp[512];
    struct addr_key dest;
};

// ---

static __always_inline void _init_pipeline_ctx(struct sk_msg_md *msg, u16 done_idx, const struct prange *pranges, struct pipeline_ctx *ctx) {
    char *data = (char *)(long)msg->data;
    char buf[64]; // a number cannot be larger than 64 bytes
    unsigned long tmp = 0;
    struct prange r = {0};

    {init}

    // struct prange r3 = pranges[3];
    // // TODO: this is a haaackkk
    // r3.idx += 1;
    // r3.len -= 1;
    // r3.len &= 0x3f;
    // bpf_probe_read_kernel(ctx->jwt_sig, r3.len, data + r3.idx);
    // ctx->jwt_sig_range = r3;

    ctx->done_idx = done_idx;
    ctx->dest = (struct addr_key){ 0 };
}
