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

#define MAX_CONNS 32768

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
    __uint(max_entries, MAX_CONNS/2);
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
    __uint(max_entries, MAX_CONNS/2);
    __type(key, struct sock_key);
    __type(value, u32);
} h2_conns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONNS/4);
    __type(key, struct data_stream);
    __type(value, struct data_stream);
} h2_streams SEC(".maps");

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
#define MAX_BYTES 0x7FFF
#define MAX_MATCHES 16
#define MAX_MATCH_MASK 15
#define MAX_STATES 512
#define MAX_TRANS 256

volatile const struct trans s2ts_h1[MAX_STATES][MAX_TRANS];
volatile const struct trans s2ts_h2[MAX_STATES][MAX_TRANS];

volatile const u32 ip4;
volatile const u32 ip4_start;
volatile const u32 ip4_end;
volatile const u32 port;
volatile const u32 tls_ip4;
volatile const u32 tls_port;
volatile const u32 gw;

struct hdr_match {
    u16 idx;
    u16 len;
    bool in_msg;
};

struct parse_res {
    struct hdr_match ms[MAX_MATCHES];
};

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

static __always_inline int _mutate_msg(struct sk_msg_md *msg, struct hdr_match m, u8 *str, u16 str_len, bool is_h2) {
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

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (is_h2) {
        if (data + 4 > data_end) return -1;
        u32 len = data[0] << 16 | data[1] << 8 | data[2];
        len += delta;
        data[0] = len >> 16;
        data[1] = len >> 8;
        data[2] = len;
    }

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

bpf_profile_def(mutate);
bpf_profile_def(mutate_prelinearize);
bpf_profile_def(mutate_postlinearize);
bpf_profile_def(mutate_alloc);
bpf_profile_def(mutate_copy);
static __always_inline int _mutate(void *msg __arg_ctx, struct hdr_match m, u8 *str, u16 str_len, bool is_skb, bool is_h2) {
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

        return bpf_map_push_elem(pqueue, key, BPF_ANY);
    }
}

static __always_inline enum pr_action _fib_query(struct addr_key *addr, bool downstream, bool sk_msg, struct sock_key *ekey) {
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

static __always_inline enum pr_action post_forward_us_conn(const struct sock_key *ukey, const struct sock_key *dkey, bool sk_msg) {
    if (dkey == NULL || ukey == NULL) return PR_DROP;

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

static __always_inline bool _is_loopback(struct addr_key *addr) {
    return addr->ip4 == 16777343;
}

// ----------------------------------------------

struct hdr_str {
    u32 len;
    u8* ptr;
};

enum h2_parse_state {
    // integers
    H2_IDX = 0,
    H2_KEY_LEN = 1,
    H2_VAL_LEN = 2,

    // strings
    H2_KEY = 3,
    H2_VAL = 4,
};

#define H2_IS_STR(ps) (ps > H2_VAL_LEN)

struct header_field {
    u8 key[32];
    u8 val[32];
};

#define STATIC_TABLE_SIZE 61

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, STATIC_TABLE_SIZE+1);
    __type(key, u32);
    __type(value, struct header_field);
} static_table SEC(".maps");

struct dynamic_table_key {
    struct sock_key conn;
    u32 idx;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct dynamic_table_key);
	__type(value, struct header_field);
} dynamic_table SEC(".maps");

struct dynamic_table_info {
    u16 size;
    u16 max_size;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, struct sock_key);
	__type(value, struct dynamic_table_info);
} dynamic_table_info SEC(".maps");

static __always_inline struct dynamic_table_key _new_table_key(const struct sk_msg_md *msg, u32 idx) {
    const struct sock_key skey = _new_sock_key_from_msg(msg);
    return (struct dynamic_table_key) {
        .conn = skey,
        .idx = idx
    };
}

static __always_inline u32 _get_h2_dt_idx(u32 idx, u32 dt_size) {
    u32 end_idx = STATIC_TABLE_SIZE + dt_size - 1;
    return (end_idx - idx) + STATIC_TABLE_SIZE + 1;
}

static __always_inline const u8* _extract_match(const u8 *data, const u8 *data_end, const struct sock_key *skey, const struct hdr_match *m, bool is_key) {
    bpf_log("extracting match { %d %d %d }", m->in_msg, m->idx, m->len);

    if (m->in_msg) {
        if (data + m->idx + m->len > data_end) return NULL;
        return data + m->idx;
    }

    struct header_field *hf = NULL;
    if (m->idx > STATIC_TABLE_SIZE) {
        struct dynamic_table_key key = (struct dynamic_table_key) {
            .conn = *skey,
            .idx = m->idx
        };

        hf = bpf_map_lookup_elem(&dynamic_table, &key);
    }
    else {
        u32 key = m->idx;
        hf = bpf_map_lookup_elem(&static_table, &key);
    }

    if (hf == NULL) return NULL;
    barrier(); // this is needed so that clang doesn't reorder the null check
    return (is_key) ? hf->key : hf->val;
}

static __always_inline void _next_h2(u16 state, u8 input, u16 *next_state, u16 *action) {
    state &= 0xFF;
    input &= 0xFF;

    struct trans t = s2ts_h2[state][input];
    if (t.state == 0 && t.action == 0) {
        t = s2ts_h2[state]['*'];
        if (t.state == 0 && t.action == 0) {
            *next_state = s_any;
            *action = 0;
            return;
        }
    }

    *next_state = t.state;
    *action = t.action;
}

__noinline __weak int _next_h2_hpack(u8 c, enum h2_parse_state *ps __arg_nonnull, u32 *n __arg_nonnull, u32 *k __arg_nonnull, u8 *j __arg_nonnull) {
    if (*ps == H2_KEY_LEN) {
        *ps = H2_KEY;
        *j = *k-1;
        *k = 0;
        *n = 0;
    }
    else if (*ps == H2_VAL_LEN) {
        *ps = H2_VAL;
        *j = *k-1;
        *k = 0;
        *n = 0;
    }
    else if (*ps == H2_IDX && ((*n == 6 && *k == 64) || (*n == 4 && *k == 0))) {
        *ps = H2_KEY_LEN;
        *j = 0;
        *k = 0;
        *n = 7;
    }
    else if ((*ps == H2_IDX && (*n == 6 || *n == 4)) || *ps == H2_KEY) {
        *ps = H2_VAL_LEN;
        *j = 0;
        *k = 0;
        *n = 7;
    }
    else {
        *ps = H2_IDX;
        *j = 0;
        *k = 0;
        *n = 4;

        if ((c & 128) == 128) {
            *n = 7;
        }
        else if ((c & 192) == 64) {
            *n = 6;
        }
    }

    return 0;
}

static __always_inline void _parse_h2_hpack(u8 c, enum h2_parse_state *ps, u32 *n, u32 *m, u32 *k, u8 *j) {
    // bpf_log("parse_hpack: c=%d, ps=%d, n=%d, m=%d, k=%d, j=%d", c, *ps, *n, *m, *k, *j);

    if (*j > 0) {
        if (H2_IS_STR(*ps)) {
            *j -= 1;
        }
        else {
            *k += (c & 127) * (1 << *m);
            *m += 7;
            *j = ((c & 128) == 128);
        }

        return;
    }

    _next_h2_hpack(c, ps, n, k, j);
    *m = 0;

    if (!H2_IS_STR(*ps)) {
        u8 mask = (1 << *n) - 1;
        *k = c & mask;
        *j = (*k == mask);
    }
}

static __always_inline int _get_h2_table_entry(const struct sk_msg_md *msg, u32 idx, u16 dt_size, struct header_field **hf) {
    if (idx == 0) {
        *hf = NULL;
        return -1;
    }

    if (idx > STATIC_TABLE_SIZE) {
        idx = _get_h2_dt_idx(idx, dt_size);

        struct dynamic_table_key key = _new_table_key(msg, idx);
        bpf_log("lookup dt: %d", idx);
        *hf = bpf_map_lookup_elem(&dynamic_table, &key);
    }
    else {
        *hf = bpf_map_lookup_elem(&static_table, &idx);
    }

    return (hf == NULL) ? -1 : idx;
}

__noinline __weak s8 _parse_h2_table_entry(const struct header_field *hf __arg_nonnull, u16 *s __arg_nonnull) {
    u8 j = 0;
    u16 a = 0;
    bpf_for(j, 0, 32) {
        u8 c = hf->key[j & 0x1F];
        if (c == 0) return -1;

        _next_h2(*s, c, s, &a);

        if ((a & a_start_capture) != 0) {
            u8 cid = a & a_id_mask & MAX_MATCH_MASK;
            return cid;
        }
    }

    return -1;
}

__noinline __weak int _add_h2_table_entry(const struct sk_msg_md *msg, u32 idx, const struct hdr_match *key __arg_nonnull, const struct hdr_match *val __arg_nonnull) {
    struct dynamic_table_key dt_key = _new_table_key(msg, idx);
    const u8 *key_ptr = _extract_match(msg->data, msg->data_end, &dt_key.conn, key, true);
    const u8 *val_ptr = _extract_match(msg->data, msg->data_end, &dt_key.conn, val, false);
    if (!key_ptr || !val_ptr) return 0;

    struct header_field dt_val = { 0 };
    u16 key_len = (key->in_msg) ? key->len & 0x1F : 0x1F;
    int res = bpf_probe_read_kernel(dt_val.key, key_len, key_ptr);
    res += bpf_probe_read_kernel(dt_val.val, val->len & 0x1F, val_ptr);

    res += bpf_map_update_elem(&dynamic_table, &dt_key, &dt_val, BPF_ANY);
    bpf_log("add to dynamic table: %d -> %d", idx, res);
    bpf_log("key { %d %d %d}", key->idx, key->len, key->in_msg);
    bpf_log("val { %d %d %d}", val->idx, val->len, val->in_msg);

    return res;
}

static __always_inline int _parse_h2_from(const struct sk_msg_md *msg, u16 start, u16 end, u16* s, struct parse_res *pres) {
    const struct sock_key skey = _new_sock_key_from_msg(msg);
    const u8 *data = msg->data;
    const u8 *data_end = msg->data_end;
    u32 len = (u32)(data_end - data) & MAX_BYTES;
    if (end < len) len = end & MAX_BYTES;

    if (len-start == 0) {
        return -1;
    }

    if (data + 9 > data_end) return -1;
    u32 stream_id = data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];

    struct dynamic_table_info *dt_info = bpf_map_lookup_elem(&dynamic_table_info, &skey);
    if (!dt_info) {
        struct dynamic_table_info new_info = {
            .size = 0,
            .max_size = 100,
        };
        bpf_map_update_elem(&dynamic_table_info, &skey, &new_info, BPF_ANY);

        dt_info = bpf_map_lookup_elem(&dynamic_table_info, &skey);
        if (!dt_info) return -1;
    }

    u32 n = 0, m = 0;
    u32 i = 0, k = 0;
    u8 j = 0;
    s8 cid = -1;
    u8 add_to_dt = 0;
    enum h2_parse_state ps = H2_IDX;
    struct hdr_match key = {
        .idx = 0,
        .len = 0,
        .in_msg = true,
    };

    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        u8 c = data[i];

        _parse_h2_hpack(c, &ps, &n, &m, &k, &j);
        if (j != 0) continue;

        if (ps == H2_IDX) {
            bpf_log("%d: parsed idx: %d, dt_size: %d", i, k, dt_info->size);

            add_to_dt = (u8)(n == 6);
            *s = s_any;
            struct header_field *hf;
            int idx = _get_h2_table_entry(msg, k, dt_info->size, &hf);
            if (hf == NULL) {
                cid = -1;
                continue;
            }

            cid = _parse_h2_table_entry(hf, s);
            if (cid >= 0) {
                // check if we are replacing the exisiting entry, or taking
                // the one in the table
                if (n == 7) {
                    bpf_log("capture: %d {%d, %d}", cid, i, k);

                    pres->ms[cid & MAX_MATCH_MASK] = (struct hdr_match) {
                        .idx = idx,
                        .len = 31,
                        .in_msg = false,
                    };
                }
            }
            key.idx = k;
            key.in_msg = false;
        }
        else if (ps == H2_KEY_LEN) {
            key.len = k;
            key.in_msg = true;
        }
        else if (ps == H2_VAL_LEN) {
            dt_info->size += add_to_dt;

            if (cid >= 0) {
                struct hdr_match val = (struct hdr_match) {
                    .idx = i + 1,
                    .len = k,
                    .in_msg = true,
                };

                // if (add_to_dt) {
                //     _add_h2_table_entry(msg, STATIC_TABLE_SIZE + dt_info->size, &key, &val);
                // }

                bpf_log("capture: %d {%d, %d} -> %s", cid, i, k);
                pres->ms[cid & MAX_MATCH_MASK] = val;
                cid = -1;
            }
        }
    }

    return i;
}

static __always_inline int _parse_h2_msg_from(const struct sk_msg_md *msg, u16 start, u16 end, u16* s, struct parse_res *pres) {
    return _parse_h2_from(msg, start, end, s, pres);
}

static __always_inline int _parse_h2_msg(struct sk_msg_md *msg, struct parse_res *pres, u8 *type) {
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + 9 > data_end) return 0;

    u32 len = data[0] << 16 | data[1] << 8 | data[2];
    *type = data[3];
    u8 flags = data[4];
    bool padded = flags & 0x08;
    u8 hdr_len = (padded) ? 10 : 9;
    u32 stream_id = data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];

    bpf_log("Parsing HTTP/2 message for stream %d with length %d, type %d, flags %d", stream_id, len, *type, flags);

    if (*type != 0x01) {
        return len + hdr_len;
    }

    u16 s = s_any;
    int res = _parse_h2_msg_from(msg, hdr_len, len+hdr_len, &s, pres);

    if (len + hdr_len > res || res < 0) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return -1;
        }

        res = _parse_h2_msg_from(msg, res, len+hdr_len, &s, pres);
    }

    if (len + hdr_len > res) return -1;

    return res;
}

static __always_inline int _get_h2_stream_id(struct sk_msg_md *msg) {
    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + 9 > data_end) return -1;

    return data[5] << 24 | data[6] << 16 | data[7] << 8 | data[8];
}

static __always_inline int _set_h2_stream_id(struct sk_msg_md *msg, u32 new_stream_id) {
    if (bpf_msg_pull_data(msg, 0, 9, 0) < 0) {
        return -1;
    }

    int stream_id = _get_h2_stream_id(msg);
    if (stream_id <= 0) return stream_id;

    u8 *data = (u8 *)(long)msg->data;
    u8 *data_end = (u8 *)(long)msg->data_end;

    if (data + 9 > data_end) return -1;

    bpf_log("Replace stream ID %u with %u", stream_id, new_stream_id);

    data[5] = new_stream_id >> 24;
    data[6] = new_stream_id >> 16;
    data[7] = new_stream_id >> 8;
    data[8] = new_stream_id;

    return 0;
}

// ----------------------------------------------

static __always_inline void _next_h1(u16 state, u8 input, u16 *next_state, u16 *action) {
    state &= 0x1FF;
    input &= 0x7F;

    struct trans t = s2ts_h1[state][input];
    if (t.state == 0 && t.action == 0) {
        t = s2ts_h1[state]['*'];
        if (t.state == 0 && t.action == 0) {
            *next_state = s_any;
            *action = 0;
            return;
        }
    }

    *next_state = t.state;
    *action = t.action;
}

static __always_inline int _parse_h1_from(const char *data, const char *data_end, u16 start, struct parse_res *pres, u32* cidx, u16 *s, u16 *null_prefix) {
    u32 len = (u32)(data_end - data) & MAX_BYTES;

    if (len-start == 0) {
        return 0;
    }

    u32 i;
    bpf_for(i, start, len+1) {
        if (data + i + 1 > data_end) break;
        char c = data[i];

        // skb clears the TLS header, but does not remove it
        if (null_prefix && c == '\0' && i == *null_prefix) {
            *null_prefix = i + 1;
            continue;
        }

        u16 a = 0;
        _next_h1(*s, c, s, &a);

        if (*s == s_any) {
            _next_h1(s_any, c, s, &a);
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

            pres->ms[rid] = (struct hdr_match) {
                .in_msg = true,
                .idx = cidx[cid],
                .len = i - cidx[cid]
            };

            cidx[cid] = i;
        }
        if ((a & a_done) != 0) {
            bpf_log("Done parsing at %d", i);
            return i+1;
        }
    }

    return -len;
}

static __always_inline int _parse_h1_msg_from(const struct sk_msg_md *msg, u16 start, struct parse_res *pres, u32* cidx, u16* s) {
    return _parse_h1_from(msg->data, msg->data_end, start, pres, cidx, s, NULL);
}

bpf_profile_def(parse);
static __always_inline int _parse_h1_msg(struct sk_msg_md *msg, struct parse_res *pres) {
    bpf_profile_start(parse);
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;
    int res = _parse_h1_msg_from(msg, 0, pres, cidx, &s);

    // check if we can pull data
    if (res < 0 && msg->size > -res) {
        if (bpf_msg_pull_data(msg, 0, msg->size, 0) < 0) {
            return res;
        }

        res = _parse_h1_msg_from(msg, -res, pres, cidx, &s);
    }

    bpf_profile_end(parse);

    return res;
}

static __always_inline int _parse_h1_skb_from(const struct __sk_buff *skb, u16 start, struct parse_res *pres, u32* cidx, u16* s, u16 *null_prefix) {
    return _parse_h1_from((char *)(long)skb->data, (char *)(long)skb->data_end, start, pres, cidx, s, null_prefix);
}

static __always_inline int _parse_h1_skb(struct __sk_buff *skb, struct parse_res *pres, u16 *null_prefix) {
    bpf_profile_start(parse);
    u32 cidx[MAX_MATCHES] = { 0 };
    u16 s = s_init;

    // TODO: Pull data gradually
    if (bpf_skb_pull_data(skb, skb->len) < 0) {
        return -1;
    }

    int res = _parse_h1_skb_from(skb, 0, pres, cidx, &s, null_prefix);

    bpf_profile_end(parse);

    return res;
}

// ----------------------------------------------

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
    struct parse_res pres = { 0 };

    int done_idx = _parse_h1_skb(skb, &pres, NULL);
    if (done_idx < 0) {
        bpf_log("Could not parse header after %dB. Corking...", skb->len);
        return 0;
    }

    struct filter_ctx *ctx = bpf_map_lookup_elem(&ctx_percpu, &percpu_key);
    if (ctx == NULL) {
        bpf_err("ERROR: Failed to init filter context");
        return SK_DROP;
    }
    _init_h1_filter_ctx((u8*)(long)skb->data, (u8*)(long)skb->data_end, &ikey, ctx, done_idx, &pres);

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

    // skb_parser is only called for non-kTLS sockets
    struct tls_size tls = { 0 };
    if (dest == NULL) {
        bpf_log("No skb verdict found, parsing now...");

        struct parse_res pres = { 0 };
        int done_idx = _parse_h1_skb(skb, &pres, &tls.header);

        if (done_idx < 0) {
            if (done_idx == -skb->len || done_idx == -skb->len + 1) {
                bpf_log("Could not parse header after %dB. Corking...", skb->len);

                return 0;
            }

            bpf_err("ERROR: Failed to parse message (%d, %d): %s", skb->len, done_idx, skb->data);
            return SK_PASS;
        }

        struct filter_ctx *ctx = bpf_map_lookup_elem(&ctx_percpu, &percpu_key);
        if (ctx == NULL) {
            bpf_err("ERROR: Failed to init filter context");
            return SK_DROP;
        }
        _init_h1_filter_ctx((u8*)(long)skb->data, (u8*)(long)skb->data_end, &ikey, ctx, done_idx, &pres);

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
    res = _fib_query(dest, !is_downstream, false, &ekey);

    if (is_downstream) {
        post_forward_ds_conn(&ikey, &ekey, false);
    }
    else {
        post_forward_us_conn(&ikey, &ekey, false);
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
            }

            bpf_log("Redirecting skb from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port);
            return SK_PASS;
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
SEC("sk_msg")
int process_msg(struct sk_msg_md *msg) {
    bpf_profile_start(sk_msg);

    struct sock_key ikey = _new_sock_key_from_msg(msg);
    bool is_downstream = _cmp_proxy_addr(&ikey.remote);
    bpf_log("Processing %dB msg from [%pI4:%u->%pI4:%u] (downstream: %d)", msg->size, &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, is_downstream);

    enum pr_action res = PR_PASS;
    struct parse_res pres = { 0 };

    bool is_h2 = (bpf_map_lookup_elem(&h2_conns, &ikey) != NULL);
    int done_idx = -1;

    if (is_h2) {
        u8 type = 0;
        done_idx = _parse_h2_msg(msg, &pres, &type);

        struct data_stream istream = {
            .conn = ikey,
            .stream_id = _get_h2_stream_id(msg),
        };
        struct data_stream *h2_dest = bpf_map_lookup_elem(&h2_streams, &istream);
        if (h2_dest != NULL) {
            _set_h2_stream_id(msg, h2_dest->stream_id);
        }

        // HEADER frames are parsed by beeline, all other frames are forwarded to the previous destination
        if (type != 1) {
            bpf_msg_apply_bytes(msg, done_idx);

            if (h2_dest == NULL) {
                bpf_log("No existing H2 destination found. Forwarding to control plane");
            }
            else {
                if (bpf_msg_redirect_hash(msg, &msg_sock_map, &h2_dest->conn, BPF_F_INGRESS) == SK_DROP) {
                    bpf_err("ERROR: Failed to redirect msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &h2_dest->conn.local.ip4, h2_dest->conn.local.port, &h2_dest->conn.remote.ip4, h2_dest->conn.remote.port);
                }
                else {
                    bpf_log("Redirecting msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &h2_dest->conn.local.ip4, h2_dest->conn.local.port, &h2_dest->conn.remote.ip4, h2_dest->conn.remote.port);
                }
            }

            return SK_PASS;
        }
    }
    else {
        done_idx = _parse_h1_msg(msg, &pres);
        if (pres.ms[0].len > 0) {
            u32 stream_id = 1;
            bpf_map_update_elem(&h2_conns, &ikey, &stream_id, BPF_ANY);
            bpf_log("Upgraded [%pI4:%u->%pI4:%u] to HTTP/2", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port);

            bpf_msg_apply_bytes(msg, 24);
            return SK_PASS;
        }
    }

    if (done_idx < 0) {
        if (done_idx == -msg->size || done_idx == -msg->size + 1) {
            bpf_log("Could not parse header after %dB. Corking...", msg->size);

            bpf_profile_start(sk_msg_cork);
            bpf_msg_cork_bytes(msg, msg->size + 1);
            bpf_profile_end(sk_msg_cork);

            return SK_PASS;
        }
        bpf_err("ERROR: Failed to parse message (%d, %d): %s", msg->size, done_idx, msg->data);
        return SK_PASS;
    }

    struct filter_ctx *ctx = bpf_map_lookup_elem(&ctx_percpu, &percpu_key);
    if (ctx == NULL) {
        bpf_err("ERROR: Failed to init filter context");
        return SK_DROP;
    }

    if (is_h2) {
        _init_h2_filter_ctx(msg->data, msg->data_end, &ikey, ctx, done_idx, &pres);
    }
    else {
        _init_h1_filter_ctx(msg->data, msg->data_end, &ikey, ctx, done_idx, &pres);
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
    res = _fib_query(&ctx->dest, !is_downstream, true, &ekey);

    if (is_downstream) {
        post_forward_ds_conn(&ikey, &ekey, true);
    }
    else {
        post_forward_us_conn(&ikey, &ekey, true);
    }

    // if it's an h2 connection, we have to store the latest
    // frame destination. this allows us to route future
    // non-HEADER frames to the correct socket
    if (is_h2 && !sock_key_is_null(&ekey) && is_downstream) {
        struct data_stream istream = {
            .conn = ikey,
            .stream_id = _get_h2_stream_id(msg),
        };

        u32 *stream_id = bpf_map_lookup_elem(&h2_conns, &ekey);
        if (stream_id != NULL) {
            // increase the stream id for the next request
            // client stream IDs are odd and increasing with every new stream
            bpf_log("Increase stream_id for [%pI4:%u->%pI4:%u] to %u", &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port, *stream_id + 2);
            *stream_id += 2;

            struct data_stream estream = {
                .conn = ekey,
                .stream_id = *stream_id,
            };

            bpf_log("Assign stream [%pI4:%u->%pI4:%u](%d) to [%pI4:%u->%pI4:%u](%d)", &istream.conn.local.ip4, istream.conn.local.port, &istream.conn.remote.ip4, istream.conn.remote.port, istream.stream_id, &estream.conn.local.ip4, estream.conn.local.port, &estream.conn.remote.ip4, estream.conn.remote.port, estream.stream_id);
            if (bpf_map_update_elem(&h2_streams, &istream, &estream, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to update h2 stream mapping");
            }
            if (bpf_map_update_elem(&h2_streams, &estream, &istream, BPF_ANY) < 0) {
                bpf_err("ERROR: Failed to update h2 stream mapping");
            }
        }
    }

    bpf_profile_end(sk_msg);

    if (res == PR_DROP) {
        bpf_err("No FIB entry found for %pI4:%u. Dropping.", &ctx->dest.ip4, ctx->dest.port);
        return SK_DROP;
    }
    else if (res == PR_PASS) {
        if (bpf_msg_redirect_hash(msg, &msg_sock_map, &ekey, BPF_F_INGRESS) == SK_DROP) {
            bpf_err("ERROR: Failed to redirect msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port);
            res = PR_UTRN;
        }
        else {
            bpf_log("Redirecting msg from [%pI4:%u->%pI4:%u] to [%pI4:%u->%pI4:%u]", &ikey.local.ip4, ikey.local.port, &ikey.remote.ip4, ikey.remote.port, &ekey.local.ip4, ekey.local.port, &ekey.remote.ip4, ekey.remote.port);
            return SK_PASS;
        }
    }
    if (res == PR_UTRN) {
        struct data_stream stream = {
            .conn = ikey,
            .stream_id = (is_h2) ? _get_h2_stream_id(msg) : 0,
        };

        if (bpf_map_update_elem(&utrn_wait_list, &stream, &ctx->dest, BPF_ANY) < 0) {
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

        // memcached does not work well with the L4FP
        bool is_memcached = skey.local.port == 11211 || skey.remote.port == 11211;
        bool local_in_network = bpf_ntohl(skey.local.ip4) >= bpf_ntohl(ip4_start) && bpf_ntohl(skey.local.ip4) <= bpf_ntohl(ip4_end);
        bool remote_in_network = bpf_ntohl(skey.remote.ip4) >= bpf_ntohl(ip4_start) && bpf_ntohl(skey.remote.ip4) <= bpf_ntohl(ip4_end);
        bool in_network = local_in_network && remote_in_network;
        bool is_gw = skey.local.ip4 == gw || skey.remote.ip4 == gw;
        bool is_proxy = _cmp_proxy_addr(&skey.remote);

        bpf_log("Established socket [%pI4:%u->%pI4:%u] (network: %d, proxy: %d)", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port, in_network, is_proxy);
        if (is_memcached) return SK_PASS;

        void *map = NULL;
        int* use_skmsg = bpf_map_lookup_elem(&sock_map_wait_list, &skey);
        if (use_skmsg != NULL) {
            map = (*use_skmsg >= 1) ? (void*)&msg_sock_map : (void*)&skb_sock_map;
            bpf_map_delete_elem(&sock_map_wait_list, &skey);
        }
        else if (is_proxy) {
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
            bpf_log("Add socket [%pI4:%u->%pI4:%u], map: %s", &skey.local.ip4, skey.local.port, &skey.remote.ip4, skey.remote.port, map_desc);

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

// SEC("syscall")
// int crypto_setup() {
//     struct bpf_crypto_ctx *cctx;
//     struct bpf_crypto_params params = {
//         .type = "shash",
//         .algo = "hmac(sha256)",
//         .key_len = key_len,
//         .authsize = 0,
//     };
//     int err = -EINVAL;
//     if (!key_len || key_len > 256) {
//         return err;
//     }

//     __builtin_memcpy(&params.key, key, 16);
//     cctx = bpf_crypto_ctx_create(&params, sizeof(params), &err);

//     if (!cctx) {
//         return -err;
//     }

//     err = _crypto_ctx_insert(cctx);
//     if (err && err != -EEXIST)
//         return -err;

//     return 0;
// }

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
