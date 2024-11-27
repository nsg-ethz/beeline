#include <linux/module.h>
#include <linux/printk.h>
#include <crypto/hash.h>
#include <linux/btf.h>

MODULE_LICENSE("GPL");

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

static struct sdesc *init_sdesc(struct crypto_shash *alg)
{
    struct sdesc *sdesc;
    int size;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(alg);
    sdesc = kmalloc(size, GFP_KERNEL);
    if (!sdesc)
        return ERR_PTR(-ENOMEM);
    sdesc->shash.tfm = alg;
    return sdesc;
}

static int calc_hash(struct crypto_shash *alg,
             const unsigned char *data, unsigned int datalen,
             unsigned char *digest) {
    struct sdesc *sdesc;
    int ret;

    sdesc = init_sdesc(alg);
    if (IS_ERR(sdesc)) {
        pr_info("can't alloc sdesc\n");
        return PTR_ERR(sdesc);
    }

    ret = crypto_shash_digest(&sdesc->shash, data, datalen, digest);
    kfree(sdesc);
    return ret;
}

static int do_sha256(const unsigned char *data, unsigned int len, unsigned char *out_digest) {
    struct crypto_shash *alg;
    char *hash_alg_name = "sha256";

    alg = crypto_alloc_shash(hash_alg_name, 0, 0);
    if(IS_ERR(alg)){
        pr_info("can't alloc alg %s\n", hash_alg_name);
        return PTR_ERR(alg);
    }
    calc_hash(alg, data, len, out_digest);

    crypto_free_shash(alg);
    return 0;
}

__bpf_kfunc_start_defs();

__bpf_kfunc void bpf_sha256(const u8 *data, unsigned int data__sz, u8 *out, unsigned int out__sz) {
    do_sha256(data, data__sz, out);
}

__bpf_kfunc_end_defs();

BTF_SET8_START(bpf_crypto_set)
BTF_ID_FLAGS(func, bpf_sha256, 0)
BTF_SET8_END(bpf_crypto_set)

static const struct btf_kfunc_id_set bpf_crypto_kfunc_set = {
        .owner = THIS_MODULE,
        .set   = &bpf_crypto_set,
};

static int crypto_init(void) {
    /* Register the BTF */
    register_btf_kfunc_id_set(BPF_PROG_TYPE_SK_MSG, &bpf_crypto_kfunc_set);
    pr_info("Load sha256 kfunc\n");
    return 0;
}

static void crypto_exit(void) {
    pr_info("Unloading sha256 kfunc\n");
}

module_init(crypto_init)
module_exit(crypto_exit)