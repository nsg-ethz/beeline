// ---
static __always_inline enum pr_action _pipeline(struct sk_msg_md *msg, struct pipeline_ctx *ctx, const struct sock_key *ikey) {
    bool is_downstream = (ikey->remote.ip4 == ip4 && ikey->remote.port == port);
    enum pr_action res = PR_DROP;

    if (is_downstream) {
        bpf_stats_add(downstream_rq_total, 1);

        {downstream}
    }
    else {
        {upstream}

        enum pr_action res = forward_us_conn(ikey, ctx);
        if (res == PR_DROP) return PR_DROP;
    }

    return PR_PASS;
}
