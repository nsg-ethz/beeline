#include <linux/types.h>
#include <linux/module.h>
#include <linux/bpf_crypto.h>
#include <crypto/hash.h>

static void *bpf_crypto_shash_alloc_tfm(const char *algo)
{
	return crypto_alloc_shash(algo, 0, 0);
}

static void bpf_crypto_shash_free_tfm(void *tfm)
{
	crypto_free_shash(tfm);
}

static int bpf_crypto_shash_has_algo(const char *algo)
{
	return crypto_has_shash(algo, CRYPTO_ALG_TYPE_SHASH, CRYPTO_ALG_TYPE_MASK);
}

static int bpf_crypto_shash_setkey(void *tfm, const u8 *key, unsigned int keylen)
{
	return crypto_shash_setkey(tfm, key, keylen);
}

static u32 bpf_crypto_shash_get_flags(void *tfm)
{
	return crypto_shash_get_flags(tfm);
}

static unsigned int bpf_crypto_shash_ivsize(void *tfm)
{
	return 0;
}

static unsigned int bpf_crypto_shash_statesize(void *tfm)
{
	return crypto_shash_statesize(tfm);
}

static int bpf_crypto_shash_encrypt(void *tfm, const u8 *src, u8 *dst,
					unsigned int len, u8 *siv)
{
	return crypto_shash_digest(tfm, src, len, dst);
}

static int bpf_crypto_shash_decrypt(void *tfm, const u8 *src, u8 *dst,
					unsigned int len, u8 *siv)
{
	return crypto_shash_digest(tfm, src, len, dst);
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

static int __init bpf_crypto_shash_init(void)
{
	return bpf_crypto_register_type(&bpf_crypto_shash_type);
}

static void __exit bpf_crypto_shash_exit(void)
{
	int err = bpf_crypto_unregister_type(&bpf_crypto_shash_type);
	WARN_ON_ONCE(err);
}

module_init(bpf_crypto_shash_init);
module_exit(bpf_crypto_shash_exit);
MODULE_LICENSE("GPL");