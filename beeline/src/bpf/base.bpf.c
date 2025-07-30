#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

struct bpf_crypto_ctx *bpf_crypto_ctx_create(const struct bpf_crypto_params *params, u32 params__sz, int *err) __ksym;
struct bpf_crypto_ctx *bpf_crypto_ctx_acquire(struct bpf_crypto_ctx *ctx) __ksym;
void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx) __ksym;
int bpf_crypto_encrypt(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *src, const struct bpf_dynptr *dst, const struct bpf_dynptr *iv) __ksym;
int bpf_crypto_digest(const struct bpf_crypto_ctx *ctx, const u8 *src, u32 src__sz, u8 *dst, u32 dst__sz) __ksym;
int bpf_base64url_encode(const u8 *src, u32 src__sz, char *dst, u32 dst__sz) __ksym;
int bpf_base64url_decode(const u8 *src, u32 src__sz, char *dst, u32 dst__sz) __ksym;
unsigned long bpf_xxhash(const u8 *src, u32 src__sz, u64 seed) __ksym;

#ifndef bpf_clamp_uminmax
#define bpf_clamp_uminmax(VAR, UMIN, UMAX)                                                         \
    asm volatile("if %0 >= %[min] goto +2\n"                                                       \
                 "%0 = %[min]\n"                                                                   \
                 "goto +2\n"                                                                       \
                 "if %0 <= %[max] goto +1\n"                                                       \
                 "%0 = %[max]\n"                                                                   \
                 : "+r"(VAR)                                                                       \
                 : [min] "i"(UMIN), [max] "i"(UMAX))
#endif

#if LOG_LEVEL == 1
    #define bpf_log(...) (0)
    #define bpf_err(...) bpf_printk(__VA_ARGS__)
#elif LOG_LEVEL == 2
    #define bpf_log(...) bpf_printk(__VA_ARGS__)
    #define bpf_err(...) bpf_printk(__VA_ARGS__)
#else
    #define bpf_log(...) (0)
    #define bpf_err(...) (0)
#endif

#if BPF_PROFILE == 1
    #define bpf_profile_def(NAME) u64 __profile_##NAME##_cnt = 0; u64 __profile_##NAME##_sum = 0
    #define bpf_profile_start(NAME) u64 __profile_##NAME##_ts = bpf_ktime_get_ns()
    #define bpf_profile_end(NAME) __sync_fetch_and_add(&__profile_##NAME##_cnt, 1); __sync_fetch_and_add(&__profile_##NAME##_sum, (bpf_ktime_get_ns() - __profile_##NAME##_ts))
    #define bpf_profile_print(NAME) bpf_printk("%s total: %llu nsecs, count: %llu", #NAME, __profile_##NAME##_sum, __profile_##NAME##_cnt)
#else
    #define bpf_profile_def(...)
    #define bpf_profile_start(...)
    #define bpf_profile_end(...)
    #define bpf_profile_print(...)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 100);
    __type(key, int);
    __type(value, u64);
} traffic_stats SEC(".maps");

#if STATS == 1
    #define bpf_stats_def(NAME) const int __stats_##NAME##_idx = __COUNTER__
    #define bpf_stats_add(NAME, VAL) u64 *__stats_val_tmp_##__LINE__ = bpf_map_lookup_elem(&traffic_stats, &__stats_##NAME##_idx); if (__stats_val_tmp_##__LINE__ != NULL) (__sync_fetch_and_add(__stats_val_tmp_##__LINE__, VAL))
#else
    #define bpf_stats_def(...)
    #define bpf_stats_add(...)
#endif

bpf_stats_def(downstream_cx_rx_bytes_total);
bpf_stats_def(downstream_cx_tx_bytes_total);
bpf_stats_def(downstream_rq_total);
bpf_stats_def(downstream_rq_1xx);
bpf_stats_def(downstream_rq_2xx);
bpf_stats_def(downstream_rq_3xx);
bpf_stats_def(downstream_rq_4xx);
bpf_stats_def(downstream_rq_5xx);

struct cctx_val {
    struct bpf_crypto_ctx __kptr *ctx;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct cctx_val);
    __uint(max_entries, 1);
} cctx_map SEC(".maps");

struct addr_key {
    u32 ip4;
    u32 port;
};

struct sock_key {
    struct addr_key local;
    struct addr_key remote;
};

struct prange {
    u16 idx;
    u16 len;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, int);
} sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct pipeline_ctx);
} ctx_percpu SEC(".maps");

enum pr_action {
    PR_DROP=0,
    PR_PASS,
    PR_UTRN
};

enum pr_sock_action {
    PR_ADD_LOCAL=0,
    PR_ADD_REMOTE,
    PR_ADD_BOTH,
};

struct fib_pqueue {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 8192);
    __type(value, struct sock_key);
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 8192);
    __type(key, struct addr_key);
	__array(values, struct fib_pqueue);
} fib_upstream SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct addr_key);
    __type(value, struct sock_key);
} fib_downstream SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, struct addr_key);
} utrn_wait_list SEC(".maps");

const u32 percpu_key = 0;

const u16 a_done = 1 << 14;
const u16 a_start_capture = 1 << 13;
const u16 a_end_capture = 1 << 12;
// if a_done -> then this is 0
// if a_start_capture -> then this is the cid
// if a_end_capture -> then this is cid | mid
const u16 a_id_mask = 0x0FFF;
const u16 a_id_1_mask = 0x0FC0;
const u16 a_id_2_mask = 0x003F;

const u16 s_init = 0;
const u16 s_any = 1;

struct trans {
    u16 state;
    u16 action;
};

// these restrictions are needed to make the verifier happy
#define MAX_BYTES 0xFFFE
#define MAX_MATCHES 32
#define MAX_MATCH_MASK 31
#define MAX_STATES 512
#define MAX_TRANS 128

volatile const struct trans s2ts[MAX_STATES][MAX_TRANS];

volatile const u32 ip4;
volatile const u32 ip4_start;
volatile const u32 ip4_end;
volatile const u32 port;
volatile const u32 gw;

{{DEFS}}

static __always_inline struct cctx_val *_cctx_val_lookup(void) {
	u32 key = 0;
	return bpf_map_lookup_elem(&cctx_map, &key);
}

static __always_inline int _crypto_ctx_insert(struct bpf_crypto_ctx *ctx) {
    struct cctx_val local, *v;
    struct bpf_crypto_ctx *old;
    u32 key = 0;
    int err;

    local.ctx = NULL;
    err = bpf_map_update_elem(&cctx_map, &key, &local, 0);
    if (err) {
        bpf_crypto_ctx_release(ctx);
        return err;
    }

    v = bpf_map_lookup_elem(&cctx_map, &key);
    if (!v) {
        bpf_crypto_ctx_release(ctx);
        return -ENOENT;
    }

    old = bpf_kptr_xchg(&v->ctx, ctx);
    if (old) {
        bpf_crypto_ctx_release(old);
        return -EEXIST;
    }

    return 0;
}

bpf_profile_def(auth);
static __always_inline enum pr_action _validate_jwt_signature(char *claims, u32 claims_len, char *sig, u32 sig_len, char *tmp) {
    bpf_profile_start(auth);

    if (claims_len == 0 || claims_len > 4096 || sig_len == 0 || sig_len > 64) {
        bpf_err("ERROR: Invalid JWT claims or signature length (%d, %d)", claims_len, sig_len);
        return PR_DROP;
    }

    struct cctx_val *cctx_val = _cctx_val_lookup();
    if (cctx_val == NULL) {
        bpf_err("ERROR: Failed to find crypto context");
        return PR_DROP;
    }

    struct bpf_crypto_ctx *cctx = cctx_val->ctx;
    if (cctx == NULL) {
        bpf_err("ERROR: Failed to find crypto context");
        return PR_DROP;
    }

    bpf_log("Verifying JWT claims: %s with signature: %s", claims, sig);

    if (bpf_crypto_digest(cctx, (const u8*)claims, claims_len & 0xFFF, (u8 *)tmp, 3072) < 0) {
        bpf_err("ERROR: Failed to digest msg");
        return PR_DROP;
    }

    u32 dig_len = 32;
    sig_len = bpf_base64url_encode((const u8 *)tmp, dig_len, (char *)(tmp+dig_len), 3072-dig_len);
    if (sig_len < 0) {
        bpf_err("ERROR: Failed to encode signature: %d", sig_len);
        return PR_DROP;
    }

    char *res = tmp + dig_len;
    if (sig_len > 50) sig_len = 50;
    res[50] = '\0';

    u32 i;
    bpf_for(i, 0, sig_len) {
        if (sig[i] != res[i]) {
            bpf_err("ERROR: Invalid JWT signature (%c != %c at %d)", sig[i], tmp[i], i);
            return PR_DROP;
        }
    }

    bpf_log("JWT signature verified");

    bpf_profile_end(auth);

    return PR_PASS;
}

bpf_profile_def(mutate);
bpf_profile_def(mutate_prelinearize);
bpf_profile_def(mutate_postlinearize);
bpf_profile_def(mutate_alloc);
bpf_profile_def(mutate_copy);
static __always_inline int _mutate(struct sk_msg_md *msg, struct prange r, char *str, u16 str_len) {
    bpf_profile_start(mutate);

    u16 len = r.len;
    u16 idx = r.idx;

    if (len > 0xFFF) return -1;
    len &= 0xFFF;

    if (idx > 0xFFFF) return -1;
    idx &= 0xFFFF;

    s16 delta = str_len - len;

    bpf_log("Increasing msg size by %d (%d-%d) at %d", delta, str_len, len, idx);

    // we first have to linearize the data
    // TODO: figure out if we have to pull the data for every single modification
    s16 end = idx + str_len;
    if (end > msg->size) end = msg->size;

    bpf_profile_start(mutate_prelinearize);
    if (bpf_msg_pull_data(msg, 0, end, 0) < 0) return -1;
    bpf_profile_end(mutate_prelinearize);

    bpf_profile_start(mutate_alloc);
    if (delta > 0) {
        if (bpf_msg_push_data(msg, idx, delta, 0) < 0) return -1;
    }
    else if (delta < 0) {
        if (bpf_msg_pop_data(msg, idx, -delta, 0) < 0) return -1;
    }
    bpf_profile_end(mutate_alloc);

    // we're done if we don't have to write anything
    if (str_len == 0) return 0;

    bpf_log("Rewriting payload (%dB) in range [%d, %d]", msg->size, idx, len);

    // at this point we have to pull the data again to get valid data pointers
    bpf_profile_start(mutate_postlinearize);
    if (bpf_msg_pull_data(msg, idx, idx+str_len, 0) < 0) return -1;
    bpf_profile_end(mutate_postlinearize);

    bpf_profile_start(mutate_copy);

    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;

    if (data + str_len > data_end) return -1;
    __builtin_memcpy(data, str, str_len);
    // u32 i;
    // bpf_for(i, 0, str_len) {
    //     if (data + i + 1 > data_end) return -1;
    //     data[i] = str[i];
    // }

    bpf_profile_end(mutate_copy);
    bpf_profile_end(mutate);

    return 0;
}

static __always_inline int _fib_insert(const struct addr_key *addr, bool downstream, const struct sock_key *key) {
    bpf_log("Insert to FIB {%pI4:%u %d} downstream: %d", addr->ip4, addr->port, downstream);
    if (downstream) {
        return bpf_map_update_elem(&fib_downstream, addr, key, BPF_ANY);
    }
    else {
        struct fib_pqueue *pqueue = bpf_map_lookup_elem(&fib_upstream, addr);
        if (pqueue == NULL) {
            bpf_err("WARN: No pqueue found for forwarding token");
            return -1;
        }

        return bpf_map_push_elem(pqueue, key, BPF_ANY);
    }
}

static __always_inline enum pr_action _fib_query(struct addr_key *addr, bool downstream, struct sock_key *ekey) {
    if (downstream) {
        struct sock_key *res_ptr;
        res_ptr = bpf_map_lookup_elem(&fib_downstream, addr);
        if (res_ptr != NULL) {
            *ekey = *res_ptr;
            return PR_PASS;
        }

        return PR_DROP;
    }

    struct fib_pqueue *pqueue = bpf_map_lookup_elem(&fib_upstream, addr);
    if (pqueue == NULL) {
        bpf_err("ERROR: No pqueue found for addr {%pI4:%u}", &addr->ip4, addr->port);
        return PR_UTRN;
    }

    struct sock_key res;
    if (bpf_map_pop_elem(pqueue, &res) < 0) {
        bpf_log("pqueue is empty");
        return PR_UTRN;
    }
    *ekey = res;

    return PR_PASS;
}

static __always_inline enum pr_action forward_us_conn(const struct sock_key *ukey, struct pipeline_ctx *ctx) {
    if (ukey == NULL || ctx == NULL) return PR_DROP;
    ctx->dest = ukey->remote;

    return PR_PASS;
}

static __always_inline enum pr_action post_forward_ds_conn(const struct sock_key *dkey, const struct sock_key *ukey, struct pipeline_ctx *ctx) {
    if (dkey == NULL || ukey == NULL || ctx == NULL) return PR_DROP;
    if (ukey->local.ip4 == 0 && ukey->remote.ip4 == 0) return PR_PASS;

    // at this point we have to ask the plugin how it wants to route
    // this request back to the client
    if (_fib_insert(&ukey->remote, true, dkey) < 0) {
        bpf_err("ERROR: Failed to set downstream route");
    }
    else {
        bpf_log("Set downstream route %pI4:%u", &ukey->remote.ip4, ukey->remote.port);
    }

    return PR_PASS;
}

static __always_inline enum pr_action post_forward_us_conn(const struct sock_key *ukey, const struct sock_key *dkey, struct pipeline_ctx *ctx) {
    if (dkey == NULL || ukey == NULL || ctx == NULL) return PR_DROP;

    // make upstream connection available for new requests
    if (_fib_insert(&ukey->local, false, ukey) < 0) {
        bpf_err("ERROR: Failed to reinsert upstream socket to FIB");
    }

    return PR_PASS;
}

{{FILTERS}}

// ----------------------------------------------

static __always_inline void _next(u16 state, u8 input, u16 *next_state, u16 *action) {
    state &= 0x1FF;
    input &= 0x7F;

    struct trans t = s2ts[state][input];
    if (t.state == 0 && t.action == 0) {
        t = s2ts[state]['*'];
        if (t.state == 0 && t.action == 0) {
            *next_state = s_any;
            *action = 0;
            return;
        }
    }

    *next_state = t.state;
    *action = t.action;
}

static __always_inline int _parse_from(const struct sk_msg_md *msg, u16 start, struct prange *pranges, u32* cidx, u16* s) {
    bpf_profile_start(parse_range);
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    u32 len = (u32)(data_end - data) & MAX_BYTES;

    if (len-start == 0) {
        return 0;
    }

    u32 i;
    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) return -i;
        char c = data[i];

        u16 a = 0;
        _next(*s, c, s, &a);

        if (*s == s_any) {
            _next(s_any, c, s, &a);
        }

        // it should never happen that any of these cases are true simultaneously
        // but it makes the verifier happy when we don't use else if here
        if ((a & a_start_capture) != 0) {
            u16 cid = a & a_id_mask & MAX_MATCH_MASK;
            bpf_log("Start capture range (%d, ?) in [%d, ...]", cid, i);
            cidx[cid] = i;
        }
        if ((a & a_end_capture) != 0) {
            u16 cid = ((a & a_id_1_mask) >> 6) & MAX_MATCH_MASK;
            u16 rid = a & a_id_2_mask & MAX_MATCH_MASK;
            bpf_log("End capture range (%d, %d) in [%d, %d]", cid, rid, cidx[cid], i - cidx[cid]);

            pranges[rid] = (struct prange) {
                .idx = cidx[cid],
                .len = i - cidx[cid]
            };

            cidx[cid] = i;
        }
        if ((a & a_done) != 0) {
            bpf_log("Done parsing at %d", i);
            return i-1;
        }
    }

    return -len;
}

static __always_inline struct sock_key _invert_sock_key(const struct sock_key *key) {
    struct sock_key inv = {
        .local = key->remote,
        .remote = key->local,
    };
    return inv;
}

bpf_profile_def(parse);
bpf_profile_def(parse_linearize);
static __always_inline int _parse(struct sk_msg_md *msg, struct prange *pranges) {
    bpf_profile_start(parse);
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;
    int res = _parse_from(msg, 0, pranges, cidx, &s);

    // check if we can pull data
    if (res < 0 && msg->size > -res) {
        bpf_profile_start(parse_linearize);
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            bpf_profile_end(parse_linearize);
            return res;
        }
        bpf_profile_end(parse_linearize);

        res = _parse_from(msg, -res, pranges, cidx, &s);
    }

    bpf_profile_end(parse);

    return res;
}

bpf_profile_def(sk_msg);
bpf_profile_def(sk_msg_cork);
SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    bpf_profile_start(sk_msg);

    // socket identifier of the ingress connection
    struct sock_key ikey = {
        .local = {
            .ip4 = msg->local_ip4,
            .port = msg->local_port
        },
        .remote = {
            .ip4 = msg->remote_ip4,
            .port = bpf_ntohl(msg->remote_port)
        }
    };

    bool is_downstream = (ikey.remote.ip4 == ip4 && ikey.remote.port == port);
    bool is_upstream = (ikey.remote.ip4 == gw && ikey.remote.port >= 12345 && ikey.remote.port < 15345);

    // in this case it's either a just established upstream connection
    // or a connection that beeline didn't handle at all
    if (!is_downstream && !is_upstream) {
        if (ikey.remote.ip4 == gw) return SK_PASS;
        struct sock_key ekey = _invert_sock_key(&ikey);

        if (bpf_msg_redirect_hash(msg, &sock_map, &ekey, BPF_F_INGRESS) == SK_DROP) {
            bpf_err("ERROR: Failed to accelerate msg from [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
        }
        else {
            bpf_log("Transport acceleration for [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
        }

        return SK_PASS;
    }

    bpf_log("Processing %dB msg from [%pI4:%u->%pI4:%u] (downstream: %d)", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    enum pr_action res = PR_PASS;
    struct prange pranges[MAX_MATCHES] = { 0 };

    int done_idx = _parse(msg, pranges);
    if (done_idx < 0) {
        if (done_idx == -msg->size) {
            bpf_log("Could not parse header after %dB. Corking...", msg->size);

            bpf_profile_start(sk_msg_cork);
            bpf_msg_cork_bytes(msg, msg->size + 1);
            bpf_profile_end(sk_msg_cork);

            return SK_PASS;
        }
        bpf_err("ERROR: Failed to parse message: %s", msg->data);
        return SK_PASS;
    }

    struct pipeline_ctx *ctx = bpf_map_lookup_elem(&ctx_percpu, &percpu_key);
    if (ctx == NULL) {
        bpf_err("ERROR: Failed to init pipeline context");
        return SK_DROP;
    }
    _init_pipeline_ctx(msg, ctx, done_idx, pranges);

    res = _pipeline(msg, ctx, &ikey);

    u32 msg_len = ctx->content_length+ctx->done_idx+2;
    bpf_log("Apply verdict to %dB (%d + %d)", msg_len, ctx->content_length, ctx->done_idx+2);
    bpf_msg_apply_bytes(msg, msg_len);

    if (is_downstream) {
        bpf_stats_add(downstream_cx_rx_bytes_total, msg_len);
    }
    else {
        bpf_stats_add(downstream_cx_tx_bytes_total, msg_len);
    }

    if (res == PR_DROP) {
        bpf_log("WARN: Drop msg from [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
        return SK_DROP;
    }
    if (res == PR_UTRN) {
        bpf_err("ERROR: Invalid UTRN");
        return SK_DROP;
    }

    struct sock_key ekey = { 0 };
    res = _fib_query(&ctx->dest, !is_downstream, &ekey);

    if (is_downstream) {
        post_forward_ds_conn(&ikey, &ekey, ctx);
    }
    else {
        post_forward_us_conn(&ikey, &ekey, ctx);
    }

    bpf_profile_end(sk_msg);

    if (res == PR_DROP) {
        bpf_err("No FIB entry found for %pI4:%u. Dropping.", &ctx->dest.ip4, ctx->dest.port);
        return SK_DROP;
    }
    else if (res == PR_PASS) {
        if (bpf_msg_redirect_hash(msg, &sock_map, &ekey, BPF_F_INGRESS) == SK_DROP) {
            bpf_err("ERROR: Failed to redirect msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port);
            res = PR_UTRN;
        }
        else {
            bpf_log("Redirecting msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port);
            return SK_PASS;
        }
    }
    else if (res == PR_UTRN) {
        if (bpf_map_update_elem(&utrn_wait_list, &ikey, &ctx->dest, BPF_ANY) < 0) {
            bpf_err("ERROR: Failed to add uturn token to wait list");
        }
        else {
            bpf_log("Add uturn to wait list [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
        }
    }

    return SK_PASS;
}

SEC("sockops")
int monitor_sockets(struct bpf_sock_ops *ops) {
    if (ops->op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB || ops->op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB) {
        // we don't want to get called anymore for this connection
        bpf_sock_ops_cb_flags_set(ops, 0);

        struct sock_key skey = {
            .local = {
                .ip4 = ops->local_ip4,
                .port = ops->local_port
            },
            .remote = {
                .ip4 = ops->remote_ip4,
                .port = bpf_ntohl(ops->remote_port)
            }
        };

        bpf_log("Established socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);

        bool local_in_network = bpf_ntohl(skey.local.ip4) >= bpf_ntohl(ip4_start) && bpf_ntohl(skey.local.ip4) <= bpf_ntohl(ip4_end);
        bool local_is_proxy = skey.local.ip4 == ip4 && skey.local.port == port;
        bool remote_in_network = bpf_ntohl(skey.remote.ip4) >= bpf_ntohl(ip4_start) && bpf_ntohl(skey.remote.ip4) <= bpf_ntohl(ip4_end);
        bool remote_is_proxy = skey.remote.ip4 == ip4 && skey.remote.port == port;
        bool is_proxy = local_is_proxy || remote_is_proxy;
        bool in_network = local_in_network && remote_in_network;

        if (is_proxy || in_network) {
            if (bpf_sock_hash_update(ops, &sock_map, &skey, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            bpf_log("Add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
        }
    }

    return SK_PASS;
}

u32 key_len = 16;
u8 key[16] = "testtest12345678";

SEC("syscall")
int crypto_setup() {
    struct bpf_crypto_ctx *cctx;
    struct bpf_crypto_params params = {
        .type = "shash",
        .algo = "hmac(sha256)",
        .key_len = key_len,
        .authsize = 0,
    };
    int err = -EINVAL;
    if (!key_len || key_len > 256) {
        return err;
    }

    __builtin_memcpy(&params.key, key, 16);
    cctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);

    if (!cctx) {
        return -err;
    }

    err = _crypto_ctx_insert(cctx);
    if (err && err != -EEXIST)
        return -err;

    return 0;
}

SEC("syscall")
int print_profile_stats() {
    bpf_profile_print(sk_msg);
    bpf_profile_print(sk_msg_cork);

    bpf_profile_print(parse);
    bpf_profile_print(parse_linearize);

    bpf_profile_print(mutate);
    bpf_profile_print(mutate_prelinearize);
    bpf_profile_print(mutate_postlinearize);
    bpf_profile_print(mutate_alloc);
    bpf_profile_print(mutate_copy);

    bpf_profile_print(auth);

    return 0;
}
