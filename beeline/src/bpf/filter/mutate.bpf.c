// ---

enum pr_action _mutate_{idx}(void *msg __arg_ctx, struct filter_ctx *ctx, bool is_skb, bool is_h2) {
    if (!ctx) return PR_DROP;

    struct hdr_match append_range = {
        .in_msg = true,
        .idx = ctx->done_idx,
        .len = 0
    };
    struct hdr_match remove_range = { 0 };
    u8 *new_hdr;
    u32 hdr_len = 0;

    {mutation}

    return PR_PASS;
}
