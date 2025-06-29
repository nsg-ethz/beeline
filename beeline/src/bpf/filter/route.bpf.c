// ---

__noinline enum pr_action forward_ds_conn(const struct sock_key *dkey, struct pipeline_ctx *ctx) {
    if (dkey == NULL || ctx == NULL) return PR_DROP;

    {routes}

    return PR_PASS;
}
