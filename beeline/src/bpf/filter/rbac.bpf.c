bpf_stats_def(http_rbac_allowed);
bpf_stats_def(http_rbac_denied);

// ---

__always_inline enum pr_action _check_rbac(struct pipeline_ctx *ctx, const struct sock_key *ikey) {
    if (!ctx) return PR_DROP;

    {policies}

    bpf_stats_add(http_rbac_allowed, 1);

    return PR_PASS;
}
