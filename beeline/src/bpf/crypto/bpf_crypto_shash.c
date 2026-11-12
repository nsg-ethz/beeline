#define pr_fmt(fmt) "%s:%s: " fmt, KBUILD_MODNAME, __func__

#include <crypto/hash.h>
#include <linux/bpf.h>
#include <linux/bpf_crypto.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/errno.h>
#include <linux/filter.h>
#include <linux/module.h>
#include <linux/types.h>

#define DYNPTR_TYPE_SHIFT	28
#define DYNPTR_SIZE_MASK	0xFFFFFF
#define DYNPTR_RDONLY_BIT	(UL(1) << (31))

// bpf_crypto_ctx is not exported, making verification fail
// because the BTF id does not match. We will cast to
// bl_crypto_ctx within the kfunc to make this work
struct bpf_crypto_ctx;
struct bl_crypto_ctx {
	const struct bpf_crypto_type *type;
	void *tfm;
	u32 siv_len;
	struct callback_head rcu;
	refcount_t usage;
};

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_crypto_digest(const struct bpf_crypto_ctx *ctx,
			    				  const u8 *src,
								  u32 src__sz,
								  u8 *dst,
								  u32 dst__sz)
{
    const struct bl_crypto_ctx *bl_ctx = (const struct bl_crypto_ctx *)ctx;

	if (!src__sz || !dst__sz)
		return -EINVAL;

	if (dst__sz < bl_ctx->siv_len)
		return -EINVAL;

	struct shash_desc *desc = (struct shash_desc *)(dst + dst__sz - bl_ctx->siv_len);
	desc->tfm = bl_ctx->tfm;

	return crypto_shash_digest(desc, src, src__sz, dst);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(crypto_kfunc_btf_ids)
BTF_ID_FLAGS(func, bpf_crypto_digest, KF_RCU)
BTF_KFUNCS_END(crypto_kfunc_btf_ids)

static const struct btf_kfunc_id_set cryto_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &crypto_kfunc_btf_ids,
};

static void *bpf_crypto_shash_alloc_tfm(const char *algo) {
	return crypto_alloc_shash(algo, 0, 0);
}

static void bpf_crypto_shash_free_tfm(void *tfm) {
	crypto_free_shash(tfm);
}

static int bpf_crypto_shash_has_algo(const char *algo) {
	return crypto_has_shash(algo, CRYPTO_ALG_TYPE_SHASH, CRYPTO_ALG_TYPE_MASK);
}

static int bpf_crypto_shash_setkey(void *tfm, const u8 *key, unsigned int keylen) {
	return crypto_shash_setkey(tfm, key, keylen);
}

static u32 bpf_crypto_shash_get_flags(void *tfm) {
	return crypto_shash_get_flags(tfm);
}

static unsigned int bpf_crypto_shash_ivsize(void *tfm) {
	return crypto_shash_descsize(tfm);
}

static unsigned int bpf_crypto_shash_statesize(void *tfm) {
	return crypto_shash_statesize(tfm);
}

static int bpf_crypto_shash_encrypt(void *tfm, const u8 *src, u8 *dst, unsigned int len, u8 *siv) {
	return -ENOSYS;
}

static int bpf_crypto_shash_decrypt(void *tfm, const u8 *src, u8 *dst, unsigned int len, u8 *siv) {
	return -ENOSYS;
}

static const struct bpf_crypto_type bpf_crypto_shash_type = {
	.alloc_tfm	= bpf_crypto_shash_alloc_tfm,
	.free_tfm	= bpf_crypto_shash_free_tfm,
	.has_algo	= bpf_crypto_shash_has_algo,
	.setkey		= bpf_crypto_shash_setkey,
	.encrypt	= bpf_crypto_shash_encrypt,
	.decrypt	= bpf_crypto_shash_decrypt,
	.ivsize		= bpf_crypto_shash_ivsize,
	.statesize	= bpf_crypto_shash_statesize,
	.get_flags	= bpf_crypto_shash_get_flags,
	.owner		= THIS_MODULE,
	.name		= "shash",
};

static int __init bpf_crypto_shash_init(void) {
	pr_info("register kfuncs\n");
	int ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &cryto_kfunc_set);
	if (ret) {
        pr_err("failed to load kfunc (%d)\n", ret);
        return ret;
    }

	pr_info("register algo\n");
	ret = bpf_crypto_register_type(&bpf_crypto_shash_type);
	if (ret) {
        pr_err("failed to register algo (%d)\n", ret);
        return ret;
    }

	pr_info("loaded\n");
	return 0;
}

static void __exit bpf_crypto_shash_exit(void) {
	pr_info("unregister algo\n");
	int err = bpf_crypto_unregister_type(&bpf_crypto_shash_type);
	WARN_ON_ONCE(err);
}

module_init(bpf_crypto_shash_init);
module_exit(bpf_crypto_shash_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A module that adds BPF hash functions");
MODULE_VERSION("1.0");
