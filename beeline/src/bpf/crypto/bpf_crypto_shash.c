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
#include <linux/xxhash.h>

#define DYNPTR_TYPE_SHIFT	28
#define DYNPTR_SIZE_MASK	0xFFFFFF
#define DYNPTR_RDONLY_BIT	(UL(1) << (31))

static const char base64url_table[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// redefinition
struct bpf_crypto_ctx {
	const struct bpf_crypto_type *type;
	void *tfm;
	u32 siv_len;
	struct callback_head rcu;
	refcount_t usage;
};

// void *__bpf_dynptr_slice(const struct bpf_dynptr *p, u32 offset,
// 				   void *buffer__opt, u32 buffer__szk);

// bool __bpf_dynptr_is_rdonly(const struct bpf_dynptr_kern *ptr)
// {
// 	return ptr->size & DYNPTR_RDONLY_BIT;
// }

// static enum bpf_dynptr_type __bpf_dynptr_get_type(const struct bpf_dynptr_kern *ptr)
// {
// 	return (ptr->size & ~(DYNPTR_RDONLY_BIT)) >> DYNPTR_TYPE_SHIFT;
// }

// u32 __bpf_dynptr_size(const struct bpf_dynptr_kern *ptr)
// {
// 	return ptr->size & DYNPTR_SIZE_MASK;
// }

// static int __bpf_dynptr_check_off_len(const struct bpf_dynptr_kern *ptr, u32 offset, u32 len)
// {
// 	u32 size = __bpf_dynptr_size(ptr);

// 	if (len > size || offset > size - len)
// 		return -E2BIG;

// 	return 0;
// }

// void *__bpf_dynptr_slice(const struct bpf_dynptr *p, u32 offset,
// 				   void *buffer__opt, u32 buffer__szk)
// {
// 	const struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;
// 	enum bpf_dynptr_type type;
// 	u32 len = buffer__szk;
// 	int err;

// 	if (!ptr->data)
// 		return NULL;

// 	err = __bpf_dynptr_check_off_len(ptr, offset, len);
// 	if (err)
// 		return NULL;

// 	type = __bpf_dynptr_get_type(ptr);

// 	switch (type) {
// 	case BPF_DYNPTR_TYPE_LOCAL:
// 	case BPF_DYNPTR_TYPE_RINGBUF:
// 		return ptr->data + ptr->offset + offset;
// 	case BPF_DYNPTR_TYPE_SKB:
// 		if (buffer__opt)
// 			return skb_header_pointer(ptr->data, ptr->offset + offset, len, buffer__opt);
// 		else
// 			return skb_pointer_if_linear(ptr->data, ptr->offset + offset, len);
// 	default:
// 		WARN_ONCE(true, "unknown dynptr type %d\n", type);
// 		return NULL;
// 	}
// }

// const void *__bpf_dynptr_data(const struct bpf_dynptr_kern *ptr, u32 len)
// {
// 	const struct bpf_dynptr *p = (struct bpf_dynptr *)ptr;

// 	return __bpf_dynptr_slice(p, 0, NULL, len);
// }

// void *__bpf_dynptr_data_rw(const struct bpf_dynptr_kern *ptr, u32 len)
// {
// 	if (__bpf_dynptr_is_rdonly(ptr))
// 		return NULL;
// 	return (void *)__bpf_dynptr_data(ptr, len);
// }

// int __bpf_crypto_digest(const struct bpf_crypto_ctx *ctx,
// 			    		const struct bpf_dynptr_kern *src,
// 			    		const struct bpf_dynptr_kern *dst,
// 			    		const struct bpf_dynptr_kern *siv) {
// 	u32 src_len, dst_len, siv_len;
// 	const u8 *psrc;
// 	u8 *pdst, *piv;

// 	if (__bpf_dynptr_is_rdonly(dst))
// 		return -EINVAL;

// 	siv_len = __bpf_dynptr_size(siv);
// 	src_len = __bpf_dynptr_size(src);
// 	dst_len = __bpf_dynptr_size(dst);
// 	if (!src_len || !dst_len || !siv_len)
// 		return -EINVAL;

// 	if (siv_len != ctx->siv_len)
// 		return -EINVAL;

// 	psrc = __bpf_dynptr_data(src, src_len);
// 	if (!psrc)
// 		return -EINVAL;
// 	pdst = __bpf_dynptr_data_rw(dst, dst_len);
// 	if (!pdst)
// 		return -EINVAL;

// 	piv = __bpf_dynptr_data_rw(siv, siv_len);
// 	if (!piv)
// 		return -EINVAL;

// 	struct shash_desc *desc = (struct shash_desc *)piv;
// 	desc->tfm = ctx->tfm;

// 	return crypto_shash_digest(desc, psrc, src_len, pdst);
// }

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_crypto_digest(const struct bpf_crypto_ctx *ctx,
			    				  const u8 *src,
								  u32 src__sz,
								  u8 *dst,
								  u32 dst__sz)
{
	if (!src__sz || !dst__sz)
		return -EINVAL;

	if (dst__sz < ctx->siv_len)
		return -EINVAL;

	struct shash_desc *desc = (struct shash_desc *)(dst + dst__sz - ctx->siv_len);
	desc->tfm = ctx->tfm;

	return crypto_shash_digest(desc, src, src__sz, dst);
}

__bpf_kfunc int bpf_base64url_encode(const u8 *src,
								  u32 src__sz,
								  char *dst,
								  u32 dst__sz)
{
	if (dst__sz < 4*(src__sz/3))
		return -EINVAL;

	u32 ac = 0;
	int bits = 0;
	int i;
	char *cp = dst;

	for (i = 0; i < src__sz; i++) {
		ac = (ac << 8) | src[i];
		bits += 8;
		do {
			bits -= 6;
			*cp++ = base64url_table[(ac >> bits) & 0x3f];
		} while (bits >= 6);
	}
	if (bits) {
		*cp++ = base64url_table[(ac << (6 - bits)) & 0x3f];
		bits -= 6;
	}

	return cp - dst;
}

__bpf_kfunc int bpf_base64url_decode(const u8 *src,
								  u32 src__sz,
								  char *dst,
								  u32 dst__sz)
{
    if (dst__sz < 3*(src__sz/4))
		return -EINVAL;

    u32 ac = 0;
	int bits = 0;
	int i;
	char *bp = dst;

	for (i = 0; i < src__sz; i++) {
		const char *p = strchr(base64url_table, src[i]);

		if (p == NULL || src[i] == 0)
			return -1;
		ac = (ac << 6) | (p - base64url_table);
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			*bp++ = (u8)(ac >> bits);
		}
	}
	if (ac & ((1 << bits) - 1))
		return -1;
	return bp - dst;
}

__bpf_kfunc unsigned long bpf_xxhash(const u8 *src,
								  u32 src__sz,
								  u64 seed)
{
    return xxhash(src, src__sz, seed);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(crypto_kfunc_btf_ids)
BTF_ID_FLAGS(func, bpf_crypto_digest, KF_RCU)
BTF_ID_FLAGS(func, bpf_base64url_encode, KF_RCU)
BTF_ID_FLAGS(func, bpf_base64url_decode, KF_RCU)
BTF_ID_FLAGS(func, bpf_xxhash, KF_RCU)
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
