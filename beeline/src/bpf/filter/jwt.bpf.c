struct bpf_crypto_ctx *bpf_crypto_ctx_create(const struct bpf_crypto_params *params, u32 params__sz, int *err) __ksym;
struct bpf_crypto_ctx *bpf_crypto_ctx_acquire(struct bpf_crypto_ctx *ctx) __ksym;
void bpf_crypto_ctx_release(struct bpf_crypto_ctx *ctx) __ksym;
int bpf_crypto_encrypt(struct bpf_crypto_ctx *ctx, const struct bpf_dynptr *src, const struct bpf_dynptr *dst, const struct bpf_dynptr *iv) __ksym;
int bpf_crypto_digest(const struct bpf_crypto_ctx *ctx, const u8 *src, u32 src__sz, u8 *dst, u32 dst__sz) __ksym;
int bpf_base64url_encode(const u8 *src, u32 src__sz, char *dst, u32 dst__sz) __ksym;

// ---

bpf_profile_def(auth);
enum pr_action authorize(struct pipeline_ctx *ctx) {
    bpf_profile_start(auth);

    if (!ctx) return PR_DROP;
    if (ctx->jwt_claims_range.len == 0 || ctx->jwt_sig_range.len == 0) {
        return PR_DROP;
    }

    struct cctx_val *cctx_val = cctx_val_lookup();
    if (cctx_val == NULL) {
        bpf_err("ERROR: Failed to find crypto context");
        return PR_DROP;
    }

    struct bpf_crypto_ctx *cctx = cctx_val->ctx;
    if (cctx == NULL) {
        bpf_err("ERROR: Failed to find crypto context");
        return PR_DROP;
    }

    bpf_log("Verifying JWT claims: %s with signature: %s", ctx->jwt_claims, ctx->jwt_sig);

    if (bpf_crypto_digest(cctx, ctx->jwt_claims, ctx->jwt_claims_range.len & 0xfff, ctx->jwt_claims, 4096) < 0) {
        bpf_err("ERROR: Failed to digest msg");
        return PR_DROP;
    }

    int sig_len = bpf_base64url_encode(ctx->jwt_claims, 32, ctx->tmp, 512);
    if (sig_len < 0) {
        bpf_err("ERROR: Failed to encode signature");
        return PR_DROP;
    }

    if (sig_len > 50) sig_len = 50;
    ctx->tmp[50] = '\0';

    u32 i;
    bpf_for(i, 0, sig_len) {
        if (ctx->jwt_sig[i] != ctx->tmp[i]) {
            bpf_log("Invalid JWT (%c != %c at %d)", ctx->jwt_sig[i], ctx->tmp[i], i);
            return PR_DROP;
        }
    }

    bpf_log("JWT verified successfully");

    bpf_profile_end(auth);

    return PR_PASS;
}

u32 key_len = {key_len};
u8 key[{key_len}] = "{key}";

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

    err = crypto_ctx_insert(cctx);
    if (err && err != -EEXIST)
        return -err;

    return 0;
}
