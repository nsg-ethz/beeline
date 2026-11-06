// ---

static __always_inline enum pr_action route_ds_{idx}(void *msg __arg_ctx, struct filter_ctx *ctx, const struct sock_key *ikey, bool is_skb, bool is_h2) {
    {route}

    return PR_PASS;
}

VERIFY(route_{idx}, route_ds_{idx}(msg, ctx, ikey, is_skb, is_h2))
