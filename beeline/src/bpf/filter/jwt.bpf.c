// ---

enum pr_action _validate_jwt_admission_{idx}(struct pipeline_ctx *ctx) {
    if (!ctx) return PR_DROP;
    if (ctx->jwt_claims_range.len == 0 || ctx->jwt_sig_range.len == 0) {
        return PR_DROP;
    }

    int claims_len = ctx->jwt_claims_range.len-37;
    claims_len &= 0x1ff;
    claims_len = bpf_base64url_decode((const u8*)ctx->jwt_claims+37, claims_len, ctx->tmp, 512);
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
