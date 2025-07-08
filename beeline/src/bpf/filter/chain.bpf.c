// ---
static __always_inline enum pr_action _pipeline(struct sk_msg_md *msg, struct pipeline_ctx *ctx, const struct sock_key *ikey) {
    bool is_downstream = (ikey->remote.ip4 == ip4 && ikey->remote.port == port);
    enum pr_action res = PR_DROP;

    bpf_log("before ctx->dest=(%d, %d)", ctx->dest.ip4, ctx->dest.port);

    if (is_downstream) {
        {downstream}
    }
    else {
        {upstream}

        enum pr_action res = forward_us_conn(ikey, ctx);
        if (res == PR_DROP) return PR_DROP;
    }

    bpf_log("after ctx->dest=(%d, %d)", ctx->dest.ip4, ctx->dest.port);

    return PR_PASS;
}
