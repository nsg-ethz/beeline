#include "beeper/http1.h"
#include "beeper/http2.h"

struct bpf_crypto_ctx *bpf_crypto_ctx_create(const struct bpf_crypto_params *params, u32 params__sz, int *err) __ksym;
struct bpf_crypto_ctx *bpf_crypto_ctx_acquire(struct bpf_crypto_ctx *ctx) __ksym;
void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx) __ksym;
int bpf_crypto_encrypt(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *src, const struct bpf_dynptr *dst, const struct bpf_dynptr *iv) __ksym;
int bpf_crypto_digest(const struct bpf_crypto_ctx *ctx, const u8 *src, u32 src__sz, u8 *dst, u32 dst__sz) __ksym;

static const char base64url_table[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static __always_inline int _base64url_value(u8 c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

// unpadded; indices derive from the iterator so the verifier sees no loop-carried state
static __always_inline int bpf_base64url_encode(const u8 *src, u32 src_len, char *dst, u32 dst_len) {
    u32 len = src_len / 3 * 4 + (src_len % 3 ? src_len % 3 + 1 : 0);
    if (len > dst_len) return -EINVAL;

    u32 g;
    bpf_for(g, 0, (src_len + 2) / 3) {
        u32 v = 0;
        for (u32 k = 0; k < 3; k++) {
            u32 idx = 3 * g + k;
            v = (v << 8) | (idx < src_len ? src[idx] : 0);
        }
        for (u32 k = 0; k < 4; k++) {
            u32 out = 4 * g + k;
            if (out < len) dst[out] = base64url_table[(v >> (18 - 6 * k)) & 0x3f];
        }
    }

    return len;
}

static __always_inline int bpf_base64url_decode(const u8 *src, u32 src_len, char *dst, u32 dst_len) {
    u32 len = src_len / 4 * 3 + (src_len % 4 ? src_len % 4 - 1 : 0);
    if (src_len % 4 == 1 || len > dst_len) return -EINVAL;

    u32 g;
    bpf_for(g, 0, (src_len + 3) / 4) {
        u32 v = 0;
        for (u32 k = 0; k < 4; k++) {
            u32 idx = 4 * g + k;
            int c = idx < src_len ? _base64url_value(src[idx]) : 0;
            if (c < 0) return -EINVAL;
            v = (v << 6) | c;
        }

        u32 n = len - 3 * g < 3 ? len - 3 * g : 3;
        // the bits after the last output byte must be zero
        if (v & (0xFFFFFF >> (8 * n))) return -EINVAL;

        for (u32 k = 0; k < 3; k++) {
            u32 out = 3 * g + k;
            if (out < len) dst[out] = v >> (16 - 8 * k);
        }
    }

    return len;
}

#define XXH64_P1 0x9E3779B185EBCA87ULL
#define XXH64_P2 0xC2B2AE3D27D4EB4FULL
#define XXH64_P3 0x165667B19E3779F9ULL
#define XXH64_P4 0x85EBCA77C2B2AE63ULL
#define XXH64_P5 0x27D4EB2F165667C5ULL

static __always_inline u64 _rotl64(u64 x, u32 r) {
    return (x << r) | (x >> (64 - r));
}

static __always_inline u64 _xxh64_round(u64 acc, u64 in) {
    return _rotl64(acc + in * XXH64_P2, 31) * XXH64_P1;
}

static __always_inline u64 _xxh64_merge(u64 acc, u64 v) {
    return (acc ^ _xxh64_round(0, v)) * XXH64_P1 + XXH64_P4;
}

// the input may be unaligned
static __always_inline u64 _read_u64(const u8 *p) {
    u64 v;
    __builtin_memcpy(&v, p, 8);
    return v;
}

// XXH64, same as the kernel's xxhash() on 64-bit
// ponytail: plain loops, only verifies for a constant len; switch to bpf_for for variable lengths
static __always_inline u64 bpf_xxhash(const u8 *src, u32 len, u64 seed) {
    u32 i = 0;
    u64 h;

    if (len >= 32) {
        u64 v1 = seed + XXH64_P1 + XXH64_P2;
        u64 v2 = seed + XXH64_P2;
        u64 v3 = seed;
        u64 v4 = seed - XXH64_P1;
        for (; i + 32 <= len; i += 32) {
            v1 = _xxh64_round(v1, _read_u64(src + i));
            v2 = _xxh64_round(v2, _read_u64(src + i + 8));
            v3 = _xxh64_round(v3, _read_u64(src + i + 16));
            v4 = _xxh64_round(v4, _read_u64(src + i + 24));
        }
        h = _rotl64(v1, 1) + _rotl64(v2, 7) + _rotl64(v3, 12) + _rotl64(v4, 18);
        h = _xxh64_merge(h, v1);
        h = _xxh64_merge(h, v2);
        h = _xxh64_merge(h, v3);
        h = _xxh64_merge(h, v4);
    } else {
        h = seed + XXH64_P5;
    }

    h += len;
    for (; i + 8 <= len; i += 8)
        h = _rotl64(h ^ _xxh64_round(0, _read_u64(src + i)), 27) * XXH64_P1 + XXH64_P4;
    if (i + 4 <= len) {
        u32 k;
        __builtin_memcpy(&k, src + i, 4);
        h = _rotl64(h ^ (u64)k * XXH64_P1, 23) * XXH64_P2 + XXH64_P3;
        i += 4;
    }
    for (; i < len; i++)
        h = _rotl64(h ^ src[i] * XXH64_P5, 11) * XXH64_P1;

    h ^= h >> 33;
    h *= XXH64_P2;
    h ^= h >> 29;
    h *= XXH64_P3;
    h ^= h >> 32;
    return h;
}

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

#define MAX_CONNS 64000

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

struct data_stream {
    struct sock_key conn;
    u32 stream_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, MAX_CONNS);
    __type(key, struct sock_key);
    __type(value, int);
} skb_sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, MAX_CONNS);
    __type(key, struct sock_key);
    __type(value, int);
} tls_msg_sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, MAX_CONNS);
    __type(key, struct sock_key);
    __type(value, int);
} msg_sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, MAX_CONNS);
    __type(key, struct sock_key);
    __type(value, int);
} net_sock_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONNS);
    __type(key, struct data_stream);
    __type(value, struct addr_key);
} utrn_wait_list SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONNS/2);
    __type(key, struct sock_key);
    __type(value, struct addr_key);
} skb_verdict SEC(".maps");

struct tls_size {
    u16 header;
    u16 trailer;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONNS/2);
    __type(key, struct sock_key);
    __type(value, struct tls_size);
} tls_sizes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNS);
    __type(key, struct sock_key);
    __type(value, int);
} sock_map_wait_list SEC(".maps");

// maps a proxy port to the pid of the instance that owns its new connections.
// It is pinned, so that after a hot reload the old instance leaves them to the new one
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} beeline_owners SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct filter_ctx);
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

struct fib_key {
    struct addr_key addr;
    u32 sk_msg;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
    __uint(max_entries, 8192);
    __type(key, struct fib_key);
	__array(values, struct fib_pqueue);
} fib_upstream SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, struct addr_key);
    __type(value, struct sock_key);
} fib_downstream SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONNS);
    __type(key, struct sock_key);
    __type(value, u32);
} h2_conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONNS);
    __type(key, struct data_stream);
    __type(value, struct data_stream);
} h2_streams SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct http_parse_res);
} pres_percpu SEC(".maps");

const u32 percpu_key = 0;

// the match ids the beeper parsers hand out for every filter context variable
#define NO_MATCH 0xFF
volatile const u8 h1_preface_mid = NO_MATCH;
volatile const u8 h1_mids[MAX_MATCHES];
volatile const u8 h2_mids[MAX_MATCHES];

BEEPER_HTTP1_PARSE_MSG(parse_h1_msg)
BEEPER_HTTP1_PARSE_SKB(parse_h1_skb)
BEEPER_HTTP2_PARSE_MSG(parse_h2_msg)
BEEPER_HTTP2_PARSE_SKB(parse_h2_skb)
BEEPER_GET_MATCH_MSG(get_h2_match_msg)
BEEPER_GET_MATCH_SKB(get_h2_match_skb)

volatile const u32 ip4;
volatile const u32 ip4_start;
volatile const u32 ip4_end;
volatile const u32 port;
volatile const u32 tls_ip4;
volatile const u32 tls_port;
volatile const u32 gw;
volatile const u32 pid;

{{DEFS}}

static __always_inline struct sock_key _new_sock_key_from_msg(const struct sk_msg_md *msg) {
    return (struct sock_key) {
        .local = {
            .ip4 = msg->local_ip4,
            .port = msg->local_port
        },
        .remote = {
            .ip4 = msg->remote_ip4,
            .port = bpf_ntohl(msg->remote_port)
        }
    };
}

static __always_inline struct sock_key _new_sock_key_from_skb(const struct __sk_buff *skb) {
    return (struct sock_key) {
        .local = {
            .ip4 = skb->remote_ip4,
            .port = bpf_ntohl(skb->remote_port)
        },
        .remote = {
            .ip4 = skb->local_ip4,
            .port = skb->local_port
        }
    };
}

static __always_inline bool sock_key_is_null(const struct sock_key *skey) {
    return skey->local.ip4 == 0 && skey->local.port == 0 && skey->remote.ip4 == 0 && skey->remote.port == 0;
}

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
static __always_inline int _mutate_msg(struct sk_msg_md *msg, struct http_match m, u8 *str, u16 str_len, bool is_h2) {
    bpf_profile_start(mutate);

    u16 len = m.len;
    u16 idx = m.idx;
    s16 delta = str_len - len;

    bpf_log("Increasing msg size by %d (%d-%d) at %d", delta, str_len, len, idx);

    // we first have to linearize the data
    // TODO: figure out if we have to pull the data for every single modification
    u32 end = idx + str_len;
    if (end > msg->size) end = msg->size;
    end &= MAX_BYTES;

    bpf_profile_start(mutate_prelinearize);
    if (bpf_msg_pull_data(msg, 0, end, 0) < 0) return -1;
    bpf_profile_end(mutate_prelinearize);

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    // if it's an H2 frame, update the length field
    if (is_h2) {
        if (data + 4 > data_end) return -1;
        u32 frame_len = data[0] << 16 | data[1] << 8 | data[2];
        frame_len += delta;
        data[0] = frame_len >> 16;
        data[1] = frame_len >> 8;
        data[2] = frame_len;
    }

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

    data = (u8 *)(long)msg->data;
    data_end = (u8 *)(long)msg->data_end;

    // at this point we have to pull the data again to get valid data pointers
    bpf_profile_start(mutate_postlinearize);
    if (bpf_msg_pull_data(msg, idx, idx+str_len, 0) < 0) return -1;
    bpf_profile_end(mutate_postlinearize);

    bpf_profile_start(mutate_copy);

    data = (u8 *)(long)msg->data;
    data_end = (u8 *)(long)msg->data_end;

    if (data + str_len > data_end) return -1;
    __builtin_memcpy(data, str, str_len);

    bpf_profile_end(mutate_copy);
    bpf_profile_end(mutate);

    return 0;
}

static __always_inline int _mutate(void *msg __arg_ctx, struct http_match m, u8 *str, u16 str_len, bool is_skb, bool is_h2) {
    if (is_skb) {
        return -1;
    }
    else {
        return _mutate_msg(msg, m, str, str_len, is_h2);
    }
}

static __always_inline int _fib_insert(const struct addr_key *addr, bool downstream, bool sk_msg, const struct sock_key *key) {
    bpf_log("Insert to FIB {%pI4:%u} downstream: %d", &addr->ip4, addr->port, downstream);
    if (downstream) {
        return bpf_map_update_elem(&fib_downstream, addr, key, BPF_ANY);
    }
    else {
        struct fib_key queue_key = {
            .addr = *addr,
            .sk_msg = (sk_msg ? 1 : 0)
        };
        struct fib_pqueue *pqueue = bpf_map_lookup_elem(&fib_upstream, &queue_key);
        if (pqueue == NULL) {
            bpf_err("ERROR: No pqueue found addr {%pI4:%u}", &addr->ip4, addr->port);
            return -1;
        }

        return bpf_map_push_elem(pqueue, key, BPF_EXIST);
    }
}

static __always_inline enum pr_action _fib_query(struct addr_key *addr, bool downstream, bool sk_msg, struct sock_key *ekey, bool is_h2) {
    if (downstream) {
        struct sock_key *res_ptr;
        res_ptr = bpf_map_lookup_elem(&fib_downstream, addr);
        if (res_ptr != NULL) {
            *ekey = *res_ptr;
            return PR_PASS;
        }

        return PR_DROP;
    }

    struct fib_key queue_key = {
        .addr = *addr,
        .sk_msg = (sk_msg ? 1 : 0)
    };
    struct fib_pqueue *pqueue = bpf_map_lookup_elem(&fib_upstream, &queue_key);
    if (pqueue == NULL) {
        bpf_err("ERROR: No pqueue found for addr {%pI4:%u}", &addr->ip4, addr->port);
        return PR_DROP;
    }

    struct sock_key res;
    if (is_h2) {
        if (bpf_map_peek_elem(pqueue, &res) < 0) return PR_UTRN;
    }
    else {
        if (bpf_map_pop_elem(pqueue, &res) < 0) return PR_UTRN;
    }
    *ekey = res;

    return PR_PASS;
}

static __always_inline enum pr_action forward_us_conn(const struct sock_key *ukey, struct filter_ctx *ctx) {
    if (ukey == NULL || ctx == NULL) return PR_DROP;
    ctx->dest = ukey->remote;

    return PR_PASS;
}

static __always_inline enum pr_action post_forward_ds_conn(const struct sock_key *dkey, const struct sock_key *ukey, bool sk_msg) {
    if (dkey == NULL || ukey == NULL) return PR_DROP;
    if (ukey->local.ip4 == 0 && ukey->remote.ip4 == 0) return PR_PASS;

    // make sure we can route the response back to the client
    if (_fib_insert(&ukey->remote, true, sk_msg, dkey) < 0) {
        bpf_err("ERROR: Failed to set downstream route");
    }
    else {
        bpf_log("Set downstream route %pI4:%u", &ukey->remote.ip4, ukey->remote.port);
    }

    return PR_PASS;
}

static __always_inline enum pr_action post_forward_us_conn(const struct sock_key *ukey, const struct sock_key *dkey, bool sk_msg, bool is_h2) {
    if (dkey == NULL || ukey == NULL) return PR_DROP;

    // H2 multiplexes the same connection
    // if (is_h2) return PR_PASS;

    // make upstream connection available for new requests
    int res = _fib_insert(&ukey->local, false, sk_msg, ukey);
    if (res < 0) {
        bpf_err("WARN: Failed to reinsert upstream socket to FIB: [%pI4:%u] (%d)", &ukey->local.ip4, ukey->local.port, res);
    }

    return PR_PASS;
}

static __always_inline struct sock_key _invert_sock_key(const struct sock_key *key) {
    struct sock_key inv = {
        .local = key->remote,
        .remote = key->local,
    };
    return inv;
}

static __always_inline bool _cmp_proxy_addr(struct addr_key *addr) {
    return ((ip4 == 0 || addr->ip4 == ip4) && addr->port == port) || ((tls_ip4 == 0 || addr->ip4 == tls_ip4) && addr->port == tls_port);
}

// ----------------------------------------------

static __always_inline int _get_h2_stream_id(const u8* data, const u8* data_end) {
    if (data + 9 > data_end) return -1;

    return data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];
}

static __always_inline int _set_h2_stream_id(u8* data, u8* data_end, u32 new_stream_id) {
    int stream_id = _get_h2_stream_id(data, data_end);
    if (stream_id <= 0) return stream_id;

    if (data + 9 > data_end) return -1;

    bpf_log("Replace stream ID %u with %u", stream_id, new_stream_id);

    data[5] = new_stream_id >> 24;
    data[6] = new_stream_id >> 16;
    data[7] = new_stream_id >> 8;
    data[8] = new_stream_id;

    return 0;
}

static __always_inline int _set_h2_stream_id_msg(struct sk_msg_md *msg, u32 new_stream_id) {
    if (bpf_msg_pull_data(msg, 0, 9, 0) < 0) {
        return -1;
    }

    return _set_h2_stream_id(msg->data, msg->data_end, new_stream_id);
}

static __always_inline int _set_h2_stream_id_skb(struct __sk_buff *skb, u32 new_stream_id) {
    if (bpf_skb_pull_data(skb, 9) < 0) {
        return -1;
    }

    return _set_h2_stream_id((u8*)(long)skb->data, (u8*)(long)skb->data_end, new_stream_id);
}

// ----------------------------------------------

// ----------------------------------------------

// every filter has a verify_* program that only inlines that filter, so the
// verifier stats of a filter can be read in isolation. They load with --verify only
#define VERIFY(name, call)                                                            \
    SEC("?sk_msg")                                                                    \
    int verify_##name(struct sk_msg_md *msg) {                                        \
        struct sock_key skey = _new_sock_key_from_msg(msg);                           \
        const struct sock_key *ikey = &skey;                                          \
        struct filter_ctx *ctx = bpf_map_lookup_elem(&ctx_percpu, &percpu_key);       \
        struct http_parse_res *pres = bpf_map_lookup_elem(&pres_percpu, &percpu_key); \
        if (ctx == NULL || pres == NULL) return SK_DROP;                              \
        bool is_skb = false;                                                          \
        bool is_h2 = bpf_map_lookup_elem(&h2_conns, ikey) != NULL;                    \
        bool is_downstream = _cmp_proxy_addr(&skey.remote);                           \
        u16 done_idx = msg->size;                                                     \
        call;                                                                         \
        return SK_PASS;                                                               \
    }

// the cost of one profiled section. Build with BPF_PROFILE=1
bpf_profile_def(telemetry);
static __always_inline void _telemetry(void) {
    bpf_profile_start(telemetry);
    bpf_profile_end(telemetry);
}

VERIFY(telemetry, _telemetry())

{{FILTERS}}

// this function will only be called if kTLS is not active for this socket
// that's also the reason why we don't set the tls_size info for this msg
bpf_profile_def(sk_skb);
SEC("sk_skb/stream_parser")
int parse_skb(struct __sk_buff *skb) {
    struct sock_key ikey = _new_sock_key_from_skb(skb);

    bool is_downstream = _cmp_proxy_addr(&ikey.remote);
    bpf_log("Parsing %dB skb from [%pI4:%u->%pI4:%u] (downstream: %d)", skb->len, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    enum pr_action res = PR_PASS;
    struct http_parse_res pres = { 0 };
    struct http2_frame frame = { 0 };

    bool is_h2 = (bpf_map_lookup_elem(&h2_conns, &ikey) != NULL);
    u32 h2_stream_id = 0;
    int done_idx = -1;

    if (is_h2) {
        done_idx = parse_h2_skb(skb, 0, &pres, &frame, NULL);
        h2_stream_id = frame.sid;
    }
    else {
        done_idx = parse_h1_skb(skb, 0, &pres, NULL);
    }

    if (done_idx <= 0) {
        bpf_err("Could not parse skb header (code: %d) after %dB. Corking...", done_idx, skb->len);
        return 0;
    }

    // some version specific processing
    if (is_h2) {
        struct data_stream istream = {
            .conn = ikey,
            .stream_id = h2_stream_id,
        };
        struct data_stream *h2_dest = bpf_map_lookup_elem(&h2_streams, &istream);
        if (h2_dest != NULL) {
            _set_h2_stream_id_skb(skb, h2_dest->stream_id);
            h2_stream_id = h2_dest->stream_id;
        }

        // HEADER frames are parsed by beeline, all other frames are forwarded to the previous destination
        bool is_first_hdr = (frame.type == 1 && frame.flags == 4);
        if (!is_first_hdr) {
            if (h2_dest == NULL) {
                bpf_log("No existing H2 destination found. Forwarding to control plane");
            }
            else {
                if (bpf_map_update_elem(&skb_verdict, &ikey, &h2_dest->conn, BPF_ANY) < 0) {
                    bpf_err("ERROR: Failed to save verdict");
                }
            }

            return done_idx;
        }
    }
    else if (h1_preface_mid < MAX_MATCHES && pres.ms[h1_preface_mid & MAX_MATCH_MASK].len > 0) {
        // upgrade the connection if we matched the H2 preface
        u32 stream_id = 1;
        bpf_map_update_elem(&h2_conns, &ikey, &stream_id, BPF_ANY);
        bpf_log("Upgraded [%pI4:%u->%pI4:%u] to HTTP/2", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);

        return 24;
    }

    struct filter_ctx *ctx = bpf_map_lookup_elem(&ctx_percpu, &percpu_key);
    if (ctx == NULL) {
        bpf_err("ERROR: Failed to init filter context");
        return SK_DROP;
    }

    if (is_h2) {
        _init_h2_filter_ctx(skb, true, &ikey, ctx, done_idx, &pres);
    }
    else {
        _init_h1_filter_ctx((u8*)(long)skb->data, (u8*)(long)skb->data_end, &ikey, ctx, done_idx, &pres);
    }

    res = _match(skb, ctx, &ikey, is_downstream, true, false);

    u32 msg_len = (ctx->content_length > 0) ? ctx->content_length+ctx->done_idx : skb->len;
    bpf_log("Apply verdict to %dB (%d + %d)", msg_len, ctx->content_length, ctx->done_idx);

    if (is_downstream) {
        bpf_stats_add(downstream_cx_rx_bytes_total, msg_len);
    }
    else {
        bpf_stats_add(downstream_cx_tx_bytes_total, msg_len);
    }

    if (bpf_map_update_elem(&skb_verdict, &ikey, &ctx->dest, BPF_ANY) < 0) {
        bpf_err("ERROR: Failed to save verdict");
    }

    return msg_len;
}

SEC("sk_skb/stream_verdict")
int process_skb(struct __sk_buff *skb) {
    bpf_profile_start(sk_skb);

    struct sock_key ikey = _new_sock_key_from_skb(skb);
    bool is_downstream = _cmp_proxy_addr(&ikey.remote);
    bpf_log("Processing %dB skb from [%pI4:%u->%pI4:%u] (downstream: %d)", skb->len, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    enum pr_action res = PR_PASS;
    struct addr_key *dest = bpf_map_lookup_elem(&skb_verdict, &ikey);
    bool is_h2 = (bpf_map_lookup_elem(&h2_conns, &ikey) != NULL);
    u32 h2_stream_id = 0;

    // skb_parser is only called for non-kTLS sockets
    struct tls_size tls = { 0 };
    if (dest == NULL) {
        bpf_log("No skb verdict found, parsing now...");

        struct http_parse_res pres = { 0 };
        struct http2_frame frame = { 0 };
        struct null_prefix null_prefix = { 0 };
        int done_idx = -1;

        if (is_h2) {
            done_idx = parse_h2_skb(skb, 0, &pres, &frame, NULL);
            h2_stream_id = frame.sid;
        }
        else {
            done_idx = parse_h1_skb(skb, 0, &pres, &null_prefix);
            tls.header = null_prefix.len;
        }

        if (done_idx <= 0) {
            return SK_DROP;
        }

        // some version specific processing
        if (is_h2) {
            struct data_stream istream = {
                .conn = ikey,
                .stream_id = h2_stream_id,
            };
            struct data_stream *h2_dest = bpf_map_lookup_elem(&h2_streams, &istream);
            if (h2_dest != NULL) {
                _set_h2_stream_id_skb(skb, h2_dest->stream_id);
                h2_stream_id = h2_dest->stream_id;
            }

            // HEADER frames are parsed by beeline, all other frames are forwarded to the previous destination
            bool is_first_hdr = (frame.type == 1 && frame.flags == 4);
            if (!is_first_hdr) {
                if (h2_dest == NULL) {
                    bpf_log("No existing H2 destination found. Forwarding to control plane");
                }
                else {
                    if (bpf_sk_redirect_hash(skb, &skb_sock_map, &h2_dest->conn, 0) == SK_DROP) {
                        bpf_err("ERROR: Failed to redirect h2 msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &h2_dest->conn.local.ip4, h2_dest->conn.local.port, &h2_dest->conn.remote.ip4, h2_dest->conn.remote.port);
                    }
                    else {
                        bpf_log("Redirecting msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &h2_dest->conn.local.ip4, h2_dest->conn.local.port, &h2_dest->conn.remote.ip4, h2_dest->conn.remote.port);
                    }
                }

                return SK_PASS;
            }
        }
        else if (h1_preface_mid < MAX_MATCHES && pres.ms[h1_preface_mid & MAX_MATCH_MASK].len > 0) {
            // upgrade the connection if we matched the H2 preface
            u32 stream_id = 1;
            bpf_map_update_elem(&h2_conns, &ikey, &stream_id, BPF_ANY);
            bpf_log("Upgraded [%pI4:%u->%pI4:%u] to HTTP/2", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);

            return SK_PASS;
        }

        struct filter_ctx *ctx = bpf_map_lookup_elem(&ctx_percpu, &percpu_key);
        if (ctx == NULL) {
            bpf_err("ERROR: Failed to init filter context");
            return SK_DROP;
        }

        if (is_h2) {
            _init_h2_filter_ctx(skb, true, &ikey, ctx, done_idx, &pres);
        }
        else {
            _init_h1_filter_ctx((u8*)(long)skb->data, (u8*)(long)skb->data_end, &ikey, ctx, done_idx, &pres);
        }

        res = _match(skb, ctx, &ikey, is_downstream, true, false);

        u32 msg_len = ctx->content_length+ctx->done_idx;
        tls.trailer = skb->len - msg_len;
        bpf_log("tls header: %d trailer: %d", tls.header, tls.trailer);

        if (is_downstream) {
            bpf_stats_add(downstream_cx_rx_bytes_total, msg_len);
        }
        else {
            bpf_stats_add(downstream_cx_tx_bytes_total, msg_len);
        }

        if (res == PR_DROP) {
            bpf_log("WARN: Drop skb from [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
            return SK_DROP;
        }
        if (res == PR_UTRN) {
            bpf_err("ERROR: Invalid UTRN");
            return SK_DROP;
        }

        dest = &ctx->dest;
    }
    else {
        bpf_map_delete_elem(&skb_verdict, &ikey);
    }

    struct sock_key ekey = { 0 };
    res = _fib_query(dest, !is_downstream, false, &ekey, is_h2);

    if (is_downstream) {
        post_forward_ds_conn(&ikey, &ekey, false);
    }
    else {
        post_forward_us_conn(&ikey, &ekey, false, is_h2);
    }

    bpf_profile_end(sk_skb);

    if (res == PR_DROP) {
        bpf_err("No FIB entry found for %pI4:%u. Dropping.", &dest->ip4, dest->port);
        return SK_DROP;
    }
    else if (res == PR_PASS) {
        if (is_downstream) {
            ekey = _invert_sock_key(&ekey);
        }

        if (bpf_sk_redirect_hash(skb, &skb_sock_map, &ekey, 0) == SK_DROP) {
            bpf_err("ERROR: Failed to redirect skb from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port);
            res = PR_UTRN;
        }
        else {
            bool remove_tls = (tls.header + tls.trailer) != 0;
            if (remove_tls && bpf_map_update_elem(&tls_sizes, &ekey, &tls, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to update TLS size for [%pI4:%u->%pI4:%u]", &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port);
                res = (!is_h2 || is_downstream) ? PR_UTRN : PR_DROP;
            }
            else {
                bpf_log("Redirecting skb from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port);
            }
        }
    }

    if (is_h2 && !sock_key_is_null(&ekey) && is_downstream) {
        // if it's an h2 connection, we have to store the latest
        // frame destination. this allows us to route future
        // non-HEADER frames to the correct socket
        u32 *next_stream_id = bpf_map_lookup_elem(&h2_conns, &ekey);
        if (next_stream_id != NULL) {
            // increase the stream id for the next request
            // client stream IDs are odd and increasing with every new stream
            __sync_fetch_and_add(next_stream_id, 2);
            u32 new_stream_id = *next_stream_id;
            bpf_log("Increase stream ID for [%pI4:%u->%pI4:%u] to %u", &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port, new_stream_id);

            // we only assign streams if redirection worked
            // the h2 stream id is increased regardless
            if (res != PR_UTRN) {
                // istream uses the old stream ID as it is meant for
                // future messages that will still bear the old ID
                struct data_stream istream = {
                    .conn = ikey,
                    .stream_id = h2_stream_id,
                };
                struct data_stream estream = {
                    .conn = ekey,
                    .stream_id = new_stream_id,
                };

                bpf_log("Assign stream [%pI4:%u->%pI4:%u](%d) to [%pI4:%u->%pI4:%u](%d)", &istream.conn.local.ip4, istream.conn.local.port, &istream.conn.remote.ip4, istream.conn.remote.port, istream.stream_id, &estream.conn.local.ip4, estream.conn.local.port, &estream.conn.remote.ip4, estream.conn.remote.port, estream.stream_id);
                if (bpf_map_update_elem(&h2_streams, &istream, &estream, BPF_ANY) < 0) {
                    bpf_err("ERROR: Failed to update h2 stream mapping");
                }
                if (bpf_map_update_elem(&h2_streams, &estream, &istream, BPF_ANY) < 0) {
                    bpf_err("ERROR: Failed to update h2 stream mapping");
                }
            }

            // update the stream ID
            _set_h2_stream_id_skb(skb, new_stream_id);
            h2_stream_id = new_stream_id;
        }
    }

    if (res == PR_UTRN) {
        struct data_stream stream = {
            .conn = ikey,
            .stream_id = 0,
        };

        if (bpf_map_update_elem(&utrn_wait_list, &stream, dest, BPF_ANY) < 0) {
            bpf_err("ERROR: Failed to add uturn token to wait list");
        }
        else {
            bpf_log("Add uturn to wait list [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
        }
    }

    return SK_PASS;
}

SEC("sk_msg")
int remove_tls(struct sk_msg_md *msg) {
    struct sock_key ikey = _new_sock_key_from_msg(msg);
    struct tls_size *tls = bpf_map_lookup_elem(&tls_sizes, &ikey);
    if (!tls) return SK_PASS;

    bpf_map_delete_elem(&tls_sizes, &ikey);
    bpf_log("Removing tls from [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);

    if (bpf_msg_pop_data(msg, 0, tls->header, 0) < 0) {
        bpf_err("ERROR: Failed to remove tls header");
    }
    if (bpf_msg_pop_data(msg, msg->size-tls->trailer, tls->trailer, 0) < 0) {
        bpf_err("ERROR: Failed to remove tls trailer");
    }

    return SK_PASS;
}

SEC("sk_msg")
int accelerate_network(struct sk_msg_md *msg) {
    bpf_profile_start(sk_msg);

    struct sock_key ikey = _new_sock_key_from_msg(msg);
    struct sock_key ekey = _invert_sock_key(&ikey);

    if (bpf_msg_redirect_hash(msg, &net_sock_map, &ekey, BPF_F_INGRESS) == SK_DROP) {
        bpf_err("ERROR: Failed to accelerate msg from [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
    }
    // else {
    //     bpf_log("Transport acceleration for [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
    // }

    return SK_PASS;
}

bpf_profile_def(sk_msg);
bpf_profile_def(sk_msg_cork);
bpf_profile_def(parse);
SEC("sk_msg")
int process_msg(struct sk_msg_md *msg) {
    bpf_profile_start(sk_msg);

    struct sock_key ikey = _new_sock_key_from_msg(msg);

    // Not sure why, but sometimes we get messages with invalid addresses
    // in that case, we cannot really do anything other than dropping it
    if (msg->local_port == 0 || msg->remote_port == 0 || msg->local_ip4 == 0 || msg->remote_ip4 == 0) {
        bpf_err("ERROR: Invalid address: [%pI4:%u->%pI4:%u] (%pI6 and %pI6)", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &msg->local_ip6, &msg->remote_ip6);
        return SK_DROP;
    }

    bool is_downstream = _cmp_proxy_addr(&ikey.remote);
    bpf_log("Processing %dB msg from [%pI4:%u->%pI4:%u] (downstream: %d)", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    enum pr_action res = PR_PASS;
    // the parse result is too large for the stack of process_msg
    struct http_parse_res *pres = bpf_map_lookup_elem(&pres_percpu, &percpu_key);
    if (pres == NULL) return SK_DROP;
    __builtin_memset(pres, 0, sizeof(*pres));
    struct http2_frame frame = { 0 };

    bool is_h2 = (bpf_map_lookup_elem(&h2_conns, &ikey) != NULL);
    u32 h2_stream_id = 0;
    int done_idx = -1;

    bpf_profile_start(parse);
    if (is_h2) {
        done_idx = parse_h2_msg(msg, pres, &frame);
        h2_stream_id = frame.sid;
    }
    else {
        done_idx = parse_h1_msg(msg, pres);
    }
    bpf_profile_end(parse);

    if (done_idx <= 0) {
        // check if we need more bytes to parse the header
        // HTTP/2 parsing returns 0 if it doesn't even manage to parse the frame header
        if (done_idx == -EAGAIN || done_idx == 0) {
            bpf_log("Could not parse msg header (code: %d, h2: %d, type: %d) from [%pI4:%u->%pI4:%u] after %dB. Corking...", done_idx, is_h2, frame.type, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, msg->size);

            // bpf_profile_start(sk_msg_cork);
            // bpf_msg_cork_bytes(msg, msg->size + 1);
            // bpf_profile_end(sk_msg_cork);

            return SK_DROP;
        }

        bpf_err("ERROR: Failed to parse message (%d, %d): %s", msg->size, done_idx, msg->data);
        return SK_DROP;
    }

    // some version specific processing
    if (is_h2) {
        struct data_stream istream = {
            .conn = ikey,
            .stream_id = h2_stream_id,
        };
        struct data_stream *h2_dest = bpf_map_lookup_elem(&h2_streams, &istream);
        if (h2_dest != NULL) {
            _set_h2_stream_id_msg(msg, h2_dest->stream_id);
            h2_stream_id = h2_dest->stream_id;
        }

        // HEADER frames are parsed by beeline, all other frames are forwarded to the previous destination
        bool is_first_hdr = (frame.type == 1 && frame.flags == 4);
        if (!is_first_hdr) {
            bpf_msg_apply_bytes(msg, done_idx);

            if (h2_dest == NULL) {
                bpf_log("No existing H2 destination found. Forwarding to control plane");
            }
            else {
                if (bpf_msg_redirect_hash(msg, &msg_sock_map, &h2_dest->conn, BPF_F_INGRESS) == SK_DROP) {
                    bpf_err("ERROR: Failed to redirect h2 msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &h2_dest->conn.local.ip4, h2_dest->conn.local.port, &h2_dest->conn.remote.ip4, h2_dest->conn.remote.port);
                }
                else {
                    bpf_log("Redirecting msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &h2_dest->conn.local.ip4, h2_dest->conn.local.port, &h2_dest->conn.remote.ip4, h2_dest->conn.remote.port);
                }
            }

            return SK_PASS;
        }
    }
    else if (h1_preface_mid < MAX_MATCHES && pres->ms[h1_preface_mid & MAX_MATCH_MASK].len > 0) {
        // upgrade the connection if we matched the H2 preface
        u32 stream_id = 1;
        bpf_map_update_elem(&h2_conns, &ikey, &stream_id, BPF_ANY);
        bpf_log("Upgraded [%pI4:%u->%pI4:%u] to HTTP/2", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);

        bpf_msg_apply_bytes(msg, 24);
        return SK_PASS;
    }

    struct filter_ctx *ctx = bpf_map_lookup_elem(&ctx_percpu, &percpu_key);
    if (ctx == NULL) {
        bpf_err("ERROR: Failed to init filter context");
        return SK_DROP;
    }

    if (is_h2) {
        _init_h2_filter_ctx(msg, false, &ikey, ctx, done_idx, pres);
    }
    else {
        _init_h1_filter_ctx(msg->data, msg->data_end, &ikey, ctx, done_idx, pres);
    }

    res = _match(msg, ctx, &ikey, is_downstream, false, is_h2);

    u32 msg_len = ctx->content_length+ctx->done_idx;
    bpf_log("Apply verdict to %dB/%dB (%d + %d)", msg_len, msg->size, ctx->content_length, ctx->done_idx);
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
    res = _fib_query(&ctx->dest, !is_downstream, true, &ekey, is_h2);

    if (is_downstream) {
        post_forward_ds_conn(&ikey, &ekey, true);
    }
    else {
        post_forward_us_conn(&ikey, &ekey, true, is_h2);
    }

    bpf_profile_end(sk_msg);

    if (res == PR_DROP) {
        bpf_err("No FIB entry found for %pI4:%u. Dropping.", &ctx->dest.ip4, ctx->dest.port);
        return SK_DROP;
    }
    else if (res == PR_PASS) {
        if (bpf_msg_redirect_hash(msg, &msg_sock_map, &ekey, BPF_F_INGRESS) == SK_DROP) {
            bpf_err("ERROR: Failed to redirect msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port);

            // if it's h2, a uturn can only be performed for downstream requests
            // if it's a response, the user space would not be able to parse it
            res = (!is_h2 || is_downstream) ? PR_UTRN : PR_DROP;
        }
        else {
            bpf_log("Redirecting msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port);
        }
    }

    if (is_h2 && !sock_key_is_null(&ekey) && is_downstream) {
        // if it's an h2 connection, we have to store the latest
        // frame destination. this allows us to route future
        // non-HEADER frames to the correct socket
        u32 *next_stream_id = bpf_map_lookup_elem(&h2_conns, &ekey);
        if (next_stream_id != NULL) {
            // increase the stream id for the next request
            // client stream IDs are odd and increasing with every new stream
            __sync_fetch_and_add(next_stream_id, 2);
            u32 new_stream_id = *next_stream_id;
            bpf_log("Increase stream ID for [%pI4:%u->%pI4:%u] to %u", &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port, new_stream_id);

            // we only assign streams if redirection worked
            // the h2 stream id is increased regardless
            if (res != PR_UTRN) {
                // istream uses the old stream ID as it is meant for
                // future messages that will still bear the old ID
                struct data_stream istream = {
                    .conn = ikey,
                    .stream_id = h2_stream_id,
                };
                struct data_stream estream = {
                    .conn = ekey,
                    .stream_id = new_stream_id,
                };

                bpf_log("Assign stream [%pI4:%u->%pI4:%u](%d) to [%pI4:%u->%pI4:%u](%d)", &istream.conn.local.ip4, istream.conn.local.port, &istream.conn.remote.ip4, istream.conn.remote.port, istream.stream_id, &estream.conn.local.ip4, estream.conn.local.port, &estream.conn.remote.ip4, estream.conn.remote.port, estream.stream_id);
                if (bpf_map_update_elem(&h2_streams, &istream, &estream, BPF_ANY) < 0) {
                    bpf_err("ERROR: Failed to update h2 stream mapping");
                }
                if (bpf_map_update_elem(&h2_streams, &estream, &istream, BPF_ANY) < 0) {
                    bpf_err("ERROR: Failed to update h2 stream mapping");
                }
            }

            // update the stream ID
            _set_h2_stream_id_msg(msg, new_stream_id);
            h2_stream_id = new_stream_id;
        }
    }

    if (res == PR_UTRN) {
        struct data_stream istream = {
            .conn = ikey,
            .stream_id = h2_stream_id,
        };

        res = PR_PASS;
        if (bpf_map_update_elem(&utrn_wait_list, &istream, &ctx->dest, BPF_ANY) < 0) {
            bpf_err("ERROR: Failed to add uturn token to wait list");
        }
        else {
            bpf_log("Add uturn to wait list [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);
        }
    }

    return res;
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

        // memcached does not work well with the L4FP
        bool is_memcached = skey.local.port == 11211 || skey.remote.port == 11211;
        bool local_in_network = bpf_ntohl(skey.local.ip4) >= bpf_ntohl(ip4_start) && bpf_ntohl(skey.local.ip4) <= bpf_ntohl(ip4_end);
        bool remote_in_network = bpf_ntohl(skey.remote.ip4) >= bpf_ntohl(ip4_start) && bpf_ntohl(skey.remote.ip4) <= bpf_ntohl(ip4_end);
        bool in_network = local_in_network && remote_in_network;
        bool is_gw = skey.local.ip4 == gw || skey.remote.ip4 == gw;
        bool is_proxy = _cmp_proxy_addr(&skey.remote);

        // bpf_log("Established socket [%pI4:%u->%pI4:%u] (network: %d, proxy: %d)", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port, in_network, is_proxy);
        if (is_memcached) return SK_PASS;

        void *map = NULL;
        int* use_skmsg = bpf_map_lookup_elem(&sock_map_wait_list, &skey);
        if (use_skmsg != NULL) {
            map = (*use_skmsg >= 1) ? (void*)&msg_sock_map : (void*)&skb_sock_map;
            bpf_map_delete_elem(&sock_map_wait_list, &skey);
        }
        else if (is_proxy) {
            u32 *owner = bpf_map_lookup_elem(&beeline_owners, &skey.remote.port);
            if (owner != NULL && *owner != pid) return SK_PASS;
            map = (skey.remote.port != tls_port) ? (void*)&msg_sock_map : (void*)&skb_sock_map;
        }
        else if (in_network && !is_gw) map = &net_sock_map;

        char map_desc[16] = "";
        if (map == &net_sock_map)
            __builtin_strcpy(map_desc, "net");
        else if (map == &msg_sock_map)
            __builtin_strcpy(map_desc, "msg");
        else if (map == &skb_sock_map)
            __builtin_strcpy(map_desc, "skb");

        if (map) {
            // bpf_log("Add socket [%pI4:%u->%pI4:%u], map: %s", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port, map_desc);

            if (bpf_sock_hash_update(ops, map, &skey, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                return SK_PASS;
            }

            if (map == &skb_sock_map) {
                if (bpf_sock_hash_update(ops, &tls_msg_sock_map, &skey, BPF_ANY) < 0) {
                    bpf_err("ERROR: Failed to add socket [%pI4:%u->%pI4:%u]", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port);
                    return SK_PASS;
                }
            }
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

    bpf_profile_print(ctx);

    bpf_profile_print(mutate);
    bpf_profile_print(mutate_prelinearize);
    bpf_profile_print(mutate_postlinearize);
    bpf_profile_print(mutate_alloc);
    bpf_profile_print(mutate_copy);

    bpf_profile_print(auth);

    return 0;
}
