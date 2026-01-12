// ---

#include <bpf/bpf_helpers.h>
static __always_inline enum pr_action _match(void *msg __arg_ctx, struct filter_ctx *ctx, const struct sock_key *ikey, bool is_downstream, bool is_skb, bool is_h2) {
    if (is_downstream) {
        bpf_stats_add(downstream_rq_total, 1);

        {downstream}

        if (_check_rbac(ctx, ikey) == PR_DROP) {
            bpf_log("RBAC: denied");
            return PR_DROP;
        }
    }
    else {
        #if STATS == 1
            if (ctx->status_code < 200) { bpf_stats_add(downstream_rq_1xx, 1); }
            else if (ctx->status_code < 300) { bpf_stats_add(downstream_rq_2xx, 1); }
            else if (ctx->status_code < 400) { bpf_stats_add(downstream_rq_3xx, 1); }
            else if (ctx->status_code < 500) { bpf_stats_add(downstream_rq_4xx, 1); }
            else if (ctx->status_code < 600) { bpf_stats_add(downstream_rq_5xx, 1); }
        #endif

        {upstream}

        if (forward_us_conn(ikey, ctx) == PR_DROP) return PR_DROP;
    }

    return PR_PASS;
}
