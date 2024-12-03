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

// redefinition
struct bpf_crypto_ctx {
	const struct bpf_crypto_type *type;
	void *tfm;
	u32 siv_len;
	struct callback_head rcu;
	refcount_t usage;
};

void *__bpf_dynptr_slice(const struct bpf_dynptr *p, u32 offset,
				   void *buffer__opt, u32 buffer__szk);
int __bpf_crypto_digest(const struct bpf_crypto_ctx *ctx,
			    					const struct bpf_dynptr_kern *src,
			    					const struct bpf_dynptr_kern *dst,
			    					const struct bpf_dynptr_kern *siv);

bool __bpf_dynptr_is_rdonly(const struct bpf_dynptr_kern *ptr)
{
	return ptr->size & DYNPTR_RDONLY_BIT;
}

static enum bpf_dynptr_type __bpf_dynptr_get_type(const struct bpf_dynptr_kern *ptr)
{
	return (ptr->size & ~(DYNPTR_RDONLY_BIT)) >> DYNPTR_TYPE_SHIFT;
}

u32 __bpf_dynptr_size(const struct bpf_dynptr_kern *ptr)
{
	return ptr->size & DYNPTR_SIZE_MASK;
}

static int __bpf_dynptr_check_off_len(const struct bpf_dynptr_kern *ptr, u32 offset, u32 len)
{
	u32 size = __bpf_dynptr_size(ptr);

	if (len > size || offset > size - len)
		return -E2BIG;

	return 0;
}

void *__bpf_dynptr_slice(const struct bpf_dynptr *p, u32 offset,
				   void *buffer__opt, u32 buffer__szk)
{
	const struct bpf_dynptr_kern *ptr = (struct bpf_dynptr_kern *)p;
	enum bpf_dynptr_type type;
	u32 len = buffer__szk;
	int err;

	if (!ptr->data)
		return NULL;

	err = __bpf_dynptr_check_off_len(ptr, offset, len);
	if (err)
		return NULL;

	type = __bpf_dynptr_get_type(ptr);

	switch (type) {
	case BPF_DYNPTR_TYPE_LOCAL:
	case BPF_DYNPTR_TYPE_RINGBUF:
		return ptr->data + ptr->offset + offset;
	case BPF_DYNPTR_TYPE_SKB:
		if (buffer__opt)
			return skb_header_pointer(ptr->data, ptr->offset + offset, len, buffer__opt);
		else
			return skb_pointer_if_linear(ptr->data, ptr->offset + offset, len);
	default:
		WARN_ONCE(true, "unknown dynptr type %d\n", type);
		return NULL;
	}
}

const void *__bpf_dynptr_data(const struct bpf_dynptr_kern *ptr, u32 len)
{
	const struct bpf_dynptr *p = (struct bpf_dynptr *)ptr;

	return __bpf_dynptr_slice(p, 0, NULL, len);
}

void *__bpf_dynptr_data_rw(const struct bpf_dynptr_kern *ptr, u32 len)
{
	if (__bpf_dynptr_is_rdonly(ptr))
		return NULL;
	return (void *)__bpf_dynptr_data(ptr, len);
}

int __bpf_crypto_digest(const struct bpf_crypto_ctx *ctx,
			    		const struct bpf_dynptr_kern *src,
			    		const struct bpf_dynptr_kern *dst,
			    		const struct bpf_dynptr_kern *siv) {
	u32 src_len, dst_len, siv_len;
	const u8 *psrc;
	u8 *pdst, *piv;

	if (__bpf_dynptr_is_rdonly(dst))
		return -EINVAL;

	siv_len = __bpf_dynptr_size(siv);
	src_len = __bpf_dynptr_size(src);
	dst_len = __bpf_dynptr_size(dst);
	if (!src_len || !dst_len || !siv_len)
		return -EINVAL;

	if (siv_len != ctx->siv_len)
		return -EINVAL;

	psrc = __bpf_dynptr_data(src, src_len);
	if (!psrc)
		return -EINVAL;
	pdst = __bpf_dynptr_data_rw(dst, dst_len);
	if (!pdst)
		return -EINVAL;

	piv = __bpf_dynptr_data_rw(siv, siv_len);
	if (!piv)
		return -EINVAL;

	struct shash_desc *desc = (struct shash_desc *)piv;
	desc->tfm = ctx->tfm;

	return crypto_shash_digest(desc, psrc, src_len, pdst);
}
__bpf_kfunc int bpf_crypto_digest(const struct bpf_crypto_ctx *ctx,
			    				  const struct bpf_dynptr *src,
								  const struct bpf_dynptr *dst,
								  const struct bpf_dynptr *siv);

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_crypto_digest(const struct bpf_crypto_ctx *ctx,
			    				  const struct bpf_dynptr *src,
								  const struct bpf_dynptr *dst,
								  const struct bpf_dynptr *siv) {
	return __bpf_crypto_digest(ctx, 
							   (const struct bpf_dynptr_kern *)src, 
							   (const struct bpf_dynptr_kern *)dst, 
							   (const struct bpf_dynptr_kern *)siv);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(crypto_kfunc_btf_ids)
// BTF_ID_FLAGS(func, bpf_crypto_digest, KF_RCU)
BTF_ID_FLAGS(func, bpf_crypto_digest)
BTF_KFUNCS_END(crypto_kfunc_btf_ids)

static const struct btf_kfunc_id_set cryto_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &crypto_kfunc_btf_ids,
};

static int bpf_crypto_digest_init(void) {
	pr_info("bpf_crypto_digest: register kfunc\n");
	int ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_UNSPEC, &cryto_kfunc_set);
	if(ret) {
        pr_err("bpf_crypto_digest: failed to load kfunc (%d)\n", ret);
        return ret;
    }

	pr_info("bpf_crypto_digest: function loaded\n");
	return 0;
}

static void bpf_crypto_digest_exit(void) {
    pr_info("bpf_crypto_digest: function unloaded\n");
}

module_init(bpf_crypto_digest_init);
module_exit(bpf_crypto_digest_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Laurin Brandner");            
MODULE_DESCRIPTION("A module that adds BPF hash functions"); 
MODULE_VERSION("1.0");                 
