volatile const struct addr_key ring_{idx}[] = {
    {ring}
};

// ---

__always_inline enum pr_action _load_balance_{idx}(struct sk_msg_md *msg, struct pipeline_ctx *ctx) {
    u32 idx = 4 % {ring_len};
    ctx->dest = ring_{idx}[idx];
}
