#include "vmlinux.h"
#include <errno.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

// struct bpf_crypto_ctx *bpf_crypto_ctx_create(const struct bpf_crypto_params *params, u32 params__sz, int *err) __ksym;
// struct bpf_crypto_ctx *bpf_crypto_ctx_acquire(struct bpf_crypto_ctx *ctx) __ksym;
// void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx) __ksym;
// int bpf_crypto_encrypt(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *src, const struct bpf_dynptr *dst, const struct bpf_dynptr *iv) __ksym;
// int bpf_crypto_digest(const struct bpf_crypto_ctx *ctx, const u8 *src, u32 src__sz, u8 *dst, u32 dst__sz) __ksym;
// int bpf_base64url_encode(const u8 *src, u32 src__sz, char *dst, u32 dst__sz) __ksym;

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

#ifdef LOG_LEVEL
    #if LOG_LEVEL == 0
        #define bpf_log(...) (0)
        #define bpf_err(...) (0)
    #elif LOG_LEVEL == 1
        #define bpf_log(...) (0)
        #define bpf_err(...) bpf_printk(__VA_ARGS__)
    #elif LOG_LEVEL == 2
        #define bpf_log(...) bpf_printk(__VA_ARGS__)
        #define bpf_err(...) bpf_printk(__VA_ARGS__)
    #endif
#else
    #define bpf_log(...) (0)
    #define bpf_err(...) (0)
#endif

#if BPF_PROFILE == 1
    #define bpf_profile_def(NAME) u64 __profile_##NAME##_cnt = 0; u64 __profile_##NAME##_sum = 0
    #define bpf_profile_start(NAME) u64 __profile_##NAME##_ts = bpf_ktime_get_ns()
    #define bpf_profile_end(NAME) __profile_##NAME##_cnt++; __profile_##NAME##_sum += (bpf_ktime_get_ns() - __profile_##NAME##_ts)
    #define bpf_profile_print(NAME) bpf_err("%s time: %lluns, cnt: %llu", #NAME, __profile_##NAME##_sum, __profile_##NAME##_cnt)
#else
    #define bpf_profile_def(...)
    #define bpf_profile_start(...)
    #define bpf_profile_end(...)
    #define bpf_profile_print(...)
#endif

// these restrictions are needed to make the verifier happy
#define MAX_BYTES 0xFFFE
#define MAX_MATCHES 16
#define MAX_MATCH_MASK 15

struct cctx_val {
    struct bpf_crypto_ctx __kptr *ctx;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct cctx_val);
    __uint(max_entries, 1);
} cctx_map SEC(".maps");

static __always_inline struct cctx_val *cctx_val_lookup(void) {
	u32 key = 0;
	return bpf_map_lookup_elem(&cctx_map, &key);
}

static __always_inline int crypto_ctx_insert(struct bpf_crypto_ctx *ctx) {
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
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct addr_key);
    __type(value, enum pr_sock_action);
} sock_wait_list SEC(".maps");

// TODO: These per-cpu maps are only necessary if the respective struct
// doesn't fit onto the stack
// TODO: percpu maps might also be necessary for forwarding and auth tokens
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct pipeline_ctx);
} ctx_percpu SEC(".maps");

const u32 a_mask = 0xFFFF0000;
const u16 a_match = 1 << 15;
const u16 a_done = 1 << 14;
const u16 a_start_capture = 1 << 13;
const u16 a_end_capture = 1 << 12;
// if a_match -> then this represents the fid
// if a_done -> then this is 0
// if a_start_capture -> then this is the cid
// if a_end_capture -> then this is cid | mid
const u16 a_id_mask = 0x0FFF;
const u16 a_id_1_mask = 0x0FC0;
const u16 a_id_2_mask = 0x003F;

const u32 s_mask = 0x0000FFFF;
const u16 s_init = 0;
const u16 s_any = 1;

volatile const u32 ip4;
volatile const u32 port;
volatile const u32 s2ts[128][256];
const u32 percpu_key = 0;

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

// TODO: this needs special care to get aligned
// user generated
struct frwd_token {
    struct addr_key addr;
    u8 direction;
    u8 path;
    u8 num_bytes_min;
    u8 padding;
};

struct fib_pqueue {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 8192);
    __type(value, struct sock_key);
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 8192);
    __type(key, struct frwd_token);
	__array(values, struct fib_pqueue);
} fib SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct frwd_token);
    __type(value, struct sock_key);
} fib_direct SEC(".maps");

// ----------------------------------------------
// plugin helpers

static __always_inline int _modify(struct sk_msg_md *msg, struct prange r, char *str, u16 str_len) {
    u16 len = r.len;
    u16 idx = r.idx;

    if (len > MAX_BYTES) return -1;
    len &= 0xFF;

    if (idx > MAX_BYTES) return -1;
    idx &= 0xFFF;

    s16 delta = str_len - len;

    bpf_log("Increasing msg size by %d (%d-%d) at %d", delta, str_len, len, idx);

    // we first have to linearize the data
    // TODO: figure out if we have to pull the data for every single modification
    if (bpf_msg_pull_data(msg, 0, idx+str_len, 0) < 0) return -1;

    if (delta > 0) {
        if (bpf_msg_push_data(msg, idx, delta, 0) < 0) return -1;
    }
    else if (delta < 0) {
        if (bpf_msg_pop_data(msg, idx, -delta, 0) < 0) return -1;
    }

    // we're done if we don't have to write anything
    if (str_len == 0) return 0;

    bpf_log("Rewriting payload (%dB) in range [%d, %d]", msg->size, idx, len);

    // at this point we have to pull the data again to get valid data pointers
    if (bpf_msg_pull_data(msg, idx, idx+str_len, 0) < 0) return -1;

    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;

    u32 i;
    bpf_for(i, 0, str_len+1) {
        if (data + i + 1 > data_end) return -1;
        data[i] = str[i];
    }

    return 0;
}

static __always_inline int _fib_insert(const struct frwd_token *ft, const struct sock_key *key) {
    bpf_log("Insert to FIB {%pI4:%u %d %d %d}", ft->addr.ip4, ft->addr.port, ft->direction, ft->path, ft->num_bytes_min);
    if (!ft->num_bytes_min) {
        return bpf_map_update_elem(&fib_direct, ft, key, BPF_ANY);
    }
    else {
        struct fib_pqueue *pqueue = bpf_map_lookup_elem(&fib, ft);
        if (pqueue == NULL) {
            bpf_err("WARN: No pqueue found for forwarding token");
            return -1;
        }

        return bpf_map_push_elem(pqueue, key, BPF_ANY);
    }
}

static __always_inline enum pr_action _fib_query(const struct sock_key *ikey, struct frwd_token *ft, struct sock_key *ekey) {
    if (!ft->num_bytes_min) {
        struct sock_key *res_ptr;
        res_ptr = bpf_map_lookup_elem(&fib_direct, ft);
        if (res_ptr != NULL) {
            *ekey = *res_ptr;
            return PR_PASS;
        }

        return PR_DROP;
    }

    struct fib_pqueue *pqueue = bpf_map_lookup_elem(&fib, ft);
    if (pqueue == NULL) {
        bpf_err("WARN: No pqueue found for forwarding token {%pI4:%u, %d, %d, %d}", &ft->addr.ip4, ft->addr.port, ft->direction, ft->path, ft->num_bytes_min);
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

// ----------------------------------------------
// compiler generated

struct pipeline_ctx {
    // generated by the compiler
    // we only need this if the headers should be mutable
    u32 done_idx;
    struct prange path_range;
    struct prange content_length_range;
    struct prange jwt_claims_range;
    struct prange jwt_sig_range;

    // provided by the user
    // TODO: back this by a single buffer, with pointers to the correct data path
    char path[4096];
    u32 content_length;
    char jwt_claims[4096];
    char jwt_sig[64];

    char tmp[512];
    struct frwd_token ft;
};

enum ft_direction {
    PR_DOWNSTREAM = 1,
    PR_UPSTREAM,
    PR_REVERSE_PROXY,
};

enum ft_backend {
    PR_SOCIAL_GRAPH = 1,
    PR_HOME_TIMELINE,
    PR_COMPOSE_POST,
    PR_POST_STORAGE,
    PR_USER_TIMELINE,
    PR_URL_SHORTEN,
    PR_USER,
    PR_MEDIA,
    PR_TEXT,
    PR_UNIQUE_ID,
    PR_USER_MENTION,
};

static __always_inline void _init_pipeline_ctx(struct sk_msg_md *msg, u16 done_idx, const struct prange *pranges, struct pipeline_ctx *ctx) {
    char *data = (char *)(long)msg->data;
    char buf[64]; // a number cannot be larger than 64 bytes
    unsigned long tmp = 0;

    struct prange r0 = pranges[0];
    r0.len &= 0xfff;
    bpf_probe_read_kernel(ctx->path, r0.len, data + r0.idx);
    ctx->path_range = r0;

    struct prange r1 = pranges[1];
    r1.len &= 0x3f;
    bpf_probe_read_kernel(buf, r1.len, data + r1.idx);
    buf[r1.len] = '\0'; // this way, we don't need an if-clause
    bpf_strtoul(buf, r1.len + 1, 10, &tmp);
    ctx->content_length = tmp;
    ctx->content_length_range = r1;

    // TODO: we should not load the val if it exceeds the string length
    struct prange r2 = pranges[2];
    r2.len &= 0xfff;
    bpf_probe_read_kernel(ctx->jwt_claims, r2.len, data + r2.idx);
    ctx->jwt_claims_range = r2;

    struct prange r3 = pranges[3];
    // TODO: this is a haaackkk
    r3.idx += 1;
    r3.len -= 1;
    r3.len &= 0x3f;
    bpf_probe_read_kernel(ctx->jwt_sig, r3.len, data + r3.idx);
    ctx->jwt_sig_range = r3;

    ctx->done_idx = done_idx;
    ctx->ft = (struct frwd_token){ 0 };
}

static __always_inline enum ft_backend _res_origin(const struct sock_key *key) {
    if (key == NULL) return 0;

    u8 lo = key->local.ip4 >> 24;
    switch (lo) {
    case 2: return PR_SOCIAL_GRAPH;
    case 6: return PR_HOME_TIMELINE;
    case 9: return PR_COMPOSE_POST;
    case 11: return PR_POST_STORAGE;
    case 15: return PR_USER_TIMELINE;
    case 19: return PR_URL_SHORTEN;
    case 23: return PR_USER;
    case 27: return PR_MEDIA;
    case 31: return PR_TEXT;
    case 33: return PR_UNIQUE_ID;
    case 35: return PR_USER_MENTION;
    default: return 0;
    }
}

// ----------------------------------------------
// user provided

struct ds_conn_state {
    u32 num_bytes;
    u32 num_reqs;
};

struct us_conn_state {
    u32 num_bytes;
    u32 num_reqs;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, struct frwd_token);
} utrn_wait_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
    __type(value, struct ds_conn_state);
} ds_conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct addr_key);
    __type(value, struct us_conn_state);
} us_conns SEC(".maps");

// enum pr_action authorize(struct pipeline_ctx *ctx) {
//     if (!ctx) return PR_DROP;
//     if (ctx->jwt_claims_range.len == 0 || ctx->jwt_sig_range.len == 0) {
//         bpf_err("ERROR: No JWT parsed");
//         return PR_DROP;
//     }

//     struct cctx_val *cctx_val = cctx_val_lookup();
//     if (cctx_val == NULL) {
//         bpf_err("ERROR: Failed to find crypto context");
//         return PR_DROP;
//     }

//     struct bpf_crypto_ctx *cctx = cctx_val->ctx;
//     if (cctx == NULL) {
//         bpf_err("ERROR: Failed to find crypto context");
//         return PR_DROP;
//     }

//     // bpf_log("Verifying JWT claims: %s with signature: %s", ctx->jwt_claims, ctx->jwt_sig);

//     if (bpf_crypto_digest(cctx, ctx->jwt_claims, ctx->jwt_claims_range.len & 0xfff, ctx->jwt_claims, 4096) < 0) {
//         bpf_err("ERROR: Failed to digest msg");
//         return PR_DROP;
//     }

//     int sig_len = bpf_base64url_encode(ctx->jwt_claims, 32, ctx->tmp, 512);
//     if (sig_len < 0) {
//         bpf_err("ERROR: Failed to encode signature");
//         return PR_DROP;
//     }

//     if (sig_len > 50) sig_len = 50;
//     ctx->tmp[50] = '\0';

//     // bpf_log("Computed signature: %s", ctx->tmp);

//     u32 i;
//     bpf_for(i, 0, sig_len) {
//         if (ctx->jwt_sig[i] != ctx->tmp[i]) {
//             bpf_err("ERROR: Invalid JWT (%c != %c at %d)", ctx->jwt_sig[i], ctx->tmp[i], i);
//             return PR_DROP;
//         }
//     }

//     bpf_log("JWT verified successfully");

//     return PR_PASS;
// }

__noinline enum pr_action update_ds_state(const struct sock_key *dkey, struct pipeline_ctx *ctx) {
    if (dkey == NULL || ctx == NULL) return PR_DROP;

    struct ds_conn_state *s = bpf_map_lookup_elem(&ds_conns, dkey);
    if (s == NULL) {
        struct ds_conn_state ns = (struct ds_conn_state) {
            .num_bytes = ctx->content_length,
            .num_reqs = 1,
        };
        bpf_map_update_elem(&ds_conns, dkey, &ns, BPF_ANY);
    }
    else {
        s->num_bytes += ctx->content_length;
        s->num_reqs++;
    }

    return PR_PASS;
}

__noinline enum pr_action update_us_state(const struct sock_key *ukey, struct pipeline_ctx *ctx) {
    if (ukey == NULL || ctx == NULL) return PR_DROP;

    const struct addr_key *rukey = &ukey->remote;
    struct us_conn_state *s = bpf_map_lookup_elem(&us_conns, rukey);
    if (s == NULL) {
        struct us_conn_state ns = (struct us_conn_state) {
            .num_bytes = ctx->content_length,
            .num_reqs = 1,
        };
        bpf_map_update_elem(&us_conns, rukey, &ns, BPF_ANY);
    }
    else {
        s->num_bytes += ctx->content_length;
        s->num_reqs++;
    }

    return PR_PASS;
}

__noinline enum pr_action forward_ds_conn(const struct sock_key *dkey, struct pipeline_ctx *ctx) {
    if (dkey == NULL || ctx == NULL) return PR_DROP;

    const char *compose_post = "/compose-post-service";
    bool path_is_compose_post = bpf_strncmp(ctx->path, sizeof(compose_post)-1, compose_post);
    const char *home_timeline = "/home-timeline-service";
    bool path_is_home_timeline = bpf_strncmp(ctx->path, sizeof(home_timeline)-1, home_timeline);
    const char *media = "/media-service";
    bool path_is_media = bpf_strncmp(ctx->path, sizeof(media)-1, media);
    const char *post_storage = "/post-storage-service";
    bool path_is_post_storage = bpf_strncmp(ctx->path, sizeof(post_storage)-1, post_storage);
    const char *social_graph = "/social-graph-service";
    bool path_is_social_graph = bpf_strncmp(ctx->path, sizeof(social_graph)-1, social_graph);
    const char *text = "/text-service";
    bool path_is_text = bpf_strncmp(ctx->path, sizeof(text)-1, text);
    const char *unique_id = "/unique-id-service";
    bool path_is_unique_id = bpf_strncmp(ctx->path, sizeof(unique_id)-1, unique_id);
    const char *url_shorten = "/url-shorten-service";
    bool path_is_url_shorten = bpf_strncmp(ctx->path, sizeof(url_shorten)-1, url_shorten);
    const char *user = "/user-service";
    bool path_is_user = bpf_strncmp(ctx->path, sizeof(user)-1, user);
    const char *user_timeline = "/user-timeline-service";
    bool path_is_user_timeline = bpf_strncmp(ctx->path, sizeof(user_timeline)-1, user_timeline);
    const char *user_mention = "/user-mention-service";
    bool path_is_user_mention = bpf_strncmp(ctx->path, sizeof(user_mention)-1, user_mention);

    if (path_is_compose_post == 0) ctx->ft.path = PR_COMPOSE_POST;
        else if (path_is_home_timeline == 0) ctx->ft.path = PR_HOME_TIMELINE;
            else if (path_is_media == 0) ctx->ft.path = PR_MEDIA;
                else if (path_is_post_storage == 0) ctx->ft.path = PR_POST_STORAGE;
                    else if (path_is_social_graph == 0) ctx->ft.path = PR_SOCIAL_GRAPH;
                        else if (path_is_text == 0) ctx->ft.path = PR_TEXT;
                            else if (path_is_unique_id == 0) ctx->ft.path = PR_UNIQUE_ID;
                                else if (path_is_url_shorten == 0) ctx->ft.path = PR_URL_SHORTEN;
                                    else if (path_is_user == 0) ctx->ft.path = PR_USER;
                                        else if (path_is_user_timeline == 0) ctx->ft.path = PR_USER_TIMELINE;
                                            else if (path_is_user_mention == 0) ctx->ft.path = PR_USER_MENTION;
                    else {
                        ctx->ft.direction = PR_REVERSE_PROXY;
                        ctx->ft.num_bytes_min = true;

                        return PR_PASS;
                    }

    ctx->ft.direction = PR_UPSTREAM;
    ctx->ft.num_bytes_min = true;

    // ctx->ft.direction = PR_REVERSE_PROXY;
    // ctx->ft.num_bytes_min = true;

    return PR_PASS;
}

__noinline enum pr_action forward_us_conn(const struct sock_key *ukey, struct pipeline_ctx *ctx) {
    if (ukey == NULL || ctx == NULL) return PR_DROP;

    ctx->ft.direction = PR_DOWNSTREAM;
    ctx->ft.addr = ukey->remote;

    return PR_PASS;
}

__noinline enum pr_action post_forward_ds_conn(const struct sock_key *dkey, const struct sock_key *ukey, struct pipeline_ctx *ctx) {
    if (dkey == NULL || ukey == NULL || ctx == NULL) return PR_DROP;
    if (ukey->local.ip4 == 0 && ukey->remote.ip4 == 0) return PR_PASS;

    // at this point we have to ask the plugin how it wants to route
    // this request back to the client
    struct frwd_token ft_inv = { 0 };
    ft_inv.direction = PR_DOWNSTREAM;
    ft_inv.addr = ukey->remote;

    if (_fib_insert(&ft_inv, dkey) < 0) {
        bpf_err("ERROR: Failed to set downstream forwarding token");
    }
    else {
        bpf_log("Set downstream forwarding token {%pI4:%u, %d, %d, %d}", &ft_inv.addr.ip4, ft_inv.addr.port, ft_inv.direction, ft_inv.path, ft_inv.num_bytes_min);
    }

    return PR_PASS;
}

__noinline enum pr_action post_forward_us_conn(const struct sock_key *ukey, const struct sock_key *dkey, struct pipeline_ctx *ctx) {
    if (dkey == NULL || ukey == NULL || ctx == NULL) return PR_DROP;
    u8 dir = (ukey->local.ip4 >> 24 == 40) ? PR_REVERSE_PROXY : PR_UPSTREAM;

    // make upstream connection available for new requests
    struct frwd_token ft = {
        .addr = { 0 },
        .direction = dir,
        .path = _res_origin(ukey),
        .num_bytes_min = true
    };
    if (_fib_insert(&ft, ukey) < 0) {
        bpf_err("ERROR: Failed to reinsert upstream socket to FIB");
    }

    return PR_PASS;
}

// ----------------------------------------------

static __always_inline void _next(u16 state, u32 input, u16 *next_state, u16 *action) {
    state &= 0x7F;
    input &= 0xFF;

    u32 sa = s2ts[state][input];
    if (sa == 0) {
        sa = s2ts[state]['*'];
        bpf_clamp_uminmax(sa, 0, 0xFFFFFFFF);
        if (sa == 0) {
            *next_state = s_any;
            *action = 0;
            return;
        }
    }

    *next_state = sa & s_mask;
    *action = (sa & a_mask) >> 16;
}

static __always_inline int _parse_from(const struct sk_msg_md *msg, u32 start, struct prange *pranges, bool *pmatches, u32* cidx) {
    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;
    u32 len = ((u32)(data_end - data) - start) & MAX_BYTES;

    if (len == 0) {
        return 0;
    }

    u16 s = s_init;
    u32 i;
    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) return -1;
        char c = data[i];

        u16 a = 0;
        _next(s, c, &s, &a);

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

            // TODO: this is a hack, for now
            cidx[cid] = i;
        }
        if ((a & a_match) != 0) {
            u16 mid = a & a_id_mask & MAX_MATCH_MASK;
            bpf_err("Match %d at %d", mid, i);
            pmatches[mid] = true;
        }
        if ((a & a_done) != 0) {
            bpf_log("Done parsing at %d", i);
            return i-1;
        }

        // this means that we failed to match the current pattern
        // but maybe a new one starts now?
        if (s == s_any) {
            _next(s_any, c, &s, &a);
        }
    }

    return -1;
}

bpf_profile_def(parse);
static __always_inline int _parse(struct sk_msg_md *msg, struct prange *pranges, bool *pmatches) {
    bpf_profile_start(parse);
    u32 cidx[MAX_MATCHES] = { 0 };
    int res = _parse_from(msg, 0, pranges, pmatches, cidx);

    // TODO: Ideally, we would do this in a loop until we have consumed the whole header
    if (res < 0) {
        u32 old_end = (long)msg->data_end - (long)msg->data;
        u32 new_end = 4096 > msg->size ? msg->size : 4096;

        bpf_msg_pull_data(msg, 0, new_end, 0);
        res = _parse_from(msg, 0, pranges, pmatches, cidx);
    }

    bpf_profile_end(parse);

    return res;
}

static __always_inline int _log_msg_range(struct sk_msg_md *msg, u16 idx, u16 len) {
    if (bpf_msg_pull_data(msg, idx, idx+len, 0) < 0) return -1;

    char *data = (char *)(long)msg->data;
    char *data_end = (char *)(long)msg->data_end;

    u16 j;
    bpf_for(j, 0, len+1) {
        if (data + j + 1 > data_end) return -1;
        bpf_log("data[%d]=%c", idx+j, data[j]);
    }

    return 0;
}

// compile-time generated
static __always_inline enum pr_action _pipeline(struct sk_msg_md *msg, struct pipeline_ctx *ctx, const struct sock_key *ikey) {
    bool is_downstream = (ikey->remote.ip4 == ip4 && ikey->remote.port == port);
    enum pr_action res = PR_DROP;

    if (is_downstream) {
        // res = authorize(ctx);
        // if (res == PR_DROP) {
        //     bpf_log("PLUGIN: Drop downstream msg");
        //     return PR_DROP;
        // }

        if (update_ds_state(ikey, ctx) != PR_PASS) {
            bpf_err("ERROR: Updating downstream connection state failed.");
        }

        // if (ctx->backend_range.len == 0) return PR_DROP;
        enum pr_action res = forward_ds_conn(ikey, ctx);
        if (res == PR_DROP) return PR_DROP;
    }
    else {
        struct us_conn_state state = { 0 };
        if (update_us_state(ikey, ctx) != PR_PASS) {
            bpf_err("ERROR: Updating upstream connection state failed.");
        }

        enum pr_action res = forward_us_conn(ikey, ctx);
        if (res == PR_DROP) return PR_DROP;
    }

    return PR_PASS;
}

bpf_profile_def(other);
SEC("sk_msg")
int msg_verdict(struct sk_msg_md *msg) {
    bpf_profile_start(other);

    // socket identifeir of the ingress connection
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
    bpf_log("Processing %dB msg from [%pI4:%u->%pI4:%u] (downstream: %d)", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    enum pr_action res = PR_PASS;
    struct prange pranges[MAX_MATCHES] = { 0 };
    bool pmatches[MAX_MATCHES] = { 0 };

    int done_idx = _parse(msg, pranges, pmatches);
    if (done_idx < 0) {
        bpf_err("ERROR: Failed to parse message: %s", msg->data);
        return SK_PASS;
    }

    struct pipeline_ctx *ctx = bpf_map_lookup_elem(&ctx_percpu, &percpu_key);
    if (ctx == NULL) {
        bpf_err("ERROR: Failed to init pipeline context");
        return SK_DROP;
    }
    _init_pipeline_ctx(msg, done_idx, pranges, ctx);

    res = _pipeline(msg, ctx, &ikey);

    u32 msg_len = ctx->content_length+ctx->done_idx+2;
    bpf_log("Apply verdict to %dB (%d + %d)", msg_len, ctx->content_length, ctx->done_idx+2);
    bpf_msg_apply_bytes(msg, msg_len);

    if (res == PR_DROP) {
        bpf_err("PLUGIN: Drop msg from [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
        return SK_DROP;
    }
    if (res == PR_UTRN) {
        bpf_err("PLUGIN: Invalid UTRN");
        return SK_DROP;
    }

    struct sock_key ekey = { 0 };
    res = _fib_query(&ikey, &ctx->ft, &ekey);

    if (is_downstream) {
        post_forward_ds_conn(&ikey, &ekey, ctx);
    }
    else {
        post_forward_us_conn(&ikey, &ekey, ctx);
    }

    bpf_profile_end(other);

    if (res == PR_DROP) {
        bpf_err("No FIB entry found for {%pI4:%u %d %d %d}. Dropping.", &ctx->ft.addr.ip4, ctx->ft.addr.port, ctx->ft.direction, ctx->ft.path, ctx->ft.num_bytes_min);
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
        if (bpf_map_update_elem(&utrn_wait_list, &ikey, &ctx->ft, BPF_ANY) < 0) {
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

        enum pr_sock_action *remote = bpf_map_lookup_elem(&sock_wait_list, &skey.remote);
        enum pr_sock_action *local = bpf_map_lookup_elem(&sock_wait_list, &skey.local);
        bool add_remote = (remote != NULL && (*remote == PR_ADD_REMOTE || *remote == PR_ADD_BOTH));
        bool add_local = (local != NULL && (*local == PR_ADD_LOCAL || *local == PR_ADD_BOTH));

        if (add_remote || add_local) {
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

// SEC("syscall")
// int crypto_setup() {
//     struct bpf_crypto_ctx *cctx;
//     struct bpf_crypto_params params = {
//         .type = "shash",
//         .algo = "hmac(sha256)",
//         // .type = "skcipher",
//         // .algo = "ecb(aes)",
//         .key_len = key_len,
//         .authsize = 0,
//     };
//     int err = -EINVAL;
//     if (!key_len || key_len > 256) {
//         return err;
//     }

//     // __builtin_memcpy(&params.algo, cipher, sizeof(cipher));
//     __builtin_memcpy(&params.key, key, 16);
//     cctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);

//     if (!cctx) {
//         return -err;
//     }

//     err = crypto_ctx_insert(cctx);
//     if (err && err != -EEXIST)
//         return -err;

//     return 0;
// }

SEC("syscall")
int print_profile_stats() {
    bpf_profile_print(other);
    bpf_profile_print(parse);

    return 0;
}
