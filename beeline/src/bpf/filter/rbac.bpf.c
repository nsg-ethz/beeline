bpf_stats_def(http_rbac_allowed);
bpf_stats_def(http_rbac_denied);

// ---

static __always_inline enum pr_action _check_rbac(struct pipeline_ctx *ctx, const struct sock_key *ikey) {
    if (!ctx) return PR_DROP;

    {policies}

    {no_match_action}
}
