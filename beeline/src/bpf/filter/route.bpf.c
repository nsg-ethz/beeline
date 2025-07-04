// ---

__noinline enum pr_action route_ds_{idx}(struct sk_msg_md *msg, const struct sock_key *dkey, struct pipeline_ctx *ctx) {
    if (dkey == NULL || ctx == NULL) return PR_DROP;

    {route}

    return PR_PASS;
}
