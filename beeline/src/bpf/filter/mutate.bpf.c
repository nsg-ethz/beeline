// ---

enum pr_action _mutate_msg_{idx}(struct sk_msg_md *msg, struct pipeline_ctx *ctx) {
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
