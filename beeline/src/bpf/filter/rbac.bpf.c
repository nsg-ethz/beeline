// ---

__always_inline enum pr_action _check_rbac(struct pipeline_ctx *ctx, const struct sock_key *ikey) {
    if (!ctx) return PR_DROP;

    {policies}

    return PR_PASS;
}
