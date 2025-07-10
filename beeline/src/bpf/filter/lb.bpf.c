volatile const struct addr_key ring_{idx}[] = {
    {ring}
};

// ---

__always_inline enum pr_action _load_balance_{idx}(struct sk_msg_md *msg, struct pipeline_ctx *ctx) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    u32 len = 128;
    if (data + len > data_end) return PR_DROP;

    u64 idx = bpf_xxhash(data, len, 0) % {ring_len};
    bpf_clamp_uminmax(idx, 0, {ring_len});
    ctx->dest = ring_{idx}[idx];
}
