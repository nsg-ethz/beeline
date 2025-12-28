// ---

enum pr_action _mutate_{idx}(void *msg __arg_ctx, struct filter_ctx *ctx, bool is_skb) {
    if (!ctx) return PR_DROP;

    struct prange append_range = {
        .idx = ctx->done_idx,
        .len = 0
    };
    struct prange remove_range = { 0 };
    char *new_hdr;

    {mutation}

    return PR_PASS;
}
