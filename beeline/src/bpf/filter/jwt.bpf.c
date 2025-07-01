enum pr_action _validate_jwt_signature(struct pipeline_ctx *ctx) {
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

    bpf_log("Verifying JWT claims: %s with signature: %s", ctx->jwt_claims, ctx->jwt_claims_range.len, ctx->jwt_sig, ctx->jwt_sig_range.len);

    if (bpf_crypto_digest(cctx, ctx->jwt_claims, ctx->jwt_claims_range.len & 0xfff, ctx->jwt_claims, 4096) < 0) {
        bpf_err("ERROR: Failed to digest msg");
        return PR_DROP;
    }

    int sig_len = bpf_base64url_encode(ctx->jwt_claims, 32, ctx->tmp, 512);
    if (sig_len < 0) {
        bpf_err("ERROR: Failed to encode signature: %d", sig_len);
        return PR_DROP;
    }

    if (sig_len > 50) sig_len = 50;
    ctx->tmp[50] = '\0';

    u32 i;
    bpf_for(i, 0, sig_len) {
        if (ctx->jwt_sig[i] != ctx->tmp[i]) {
            bpf_log("Invalid JWT signature (%c != %c at %d)", ctx->jwt_sig[i], ctx->tmp[i], i);
            return PR_DROP;
        }
    }

    bpf_log("JWT signature verified");

    bpf_profile_end(auth);

    return PR_PASS;
}

// ---

enum pr_action _validate_jwt_admission_{idx}(struct pipeline_ctx *ctx) {
    if (!ctx) return PR_DROP;
    if (ctx->jwt_claims_range.len == 0 || ctx->jwt_sig_range.len == 0) {
        return PR_DROP;
    }

    int claims_len = ctx->jwt_claims_range.len-37;
    claims_len &= 0xff;
    claims_len = bpf_base64url_decode(ctx->jwt_claims+37, claims_len, ctx->tmp, 512);
    if (claims_len < 0) {
        bpf_err("ERROR: Failed to decode claims: %d", claims_len);
        return PR_DROP;
    }

    if (claims_len > 512) claims_len = 512;

    bpf_log("Decoded claims: %s", ctx->tmp);

    char* adm;
    u32 adm_len;
    bool admitted;
    u32 i, j;

    {admission}

    return PR_PASS;
}
