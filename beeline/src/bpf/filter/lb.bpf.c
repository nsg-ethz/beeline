volatile const struct addr_key ring_{idx}[] = {
    {ring}
};

// ---

static __always_inline enum pr_action _load_balance_{idx}(struct sk_msg_md *msg, struct filter_ctx *ctx, const struct sock_key *ikey) {
    u64 idx = bpf_xxhash((const u8 *)ikey, sizeof(struct sock_key), 0) % {ring_len};
    bpf_clamp_uminmax(idx, 0, {ring_len});
    ctx->dest = ring_{idx}[idx];

        bpf_log("Load balancing packet to destination {%pI4:%u}", &ctx->dest.ip4, ctx->dest.port);
}
