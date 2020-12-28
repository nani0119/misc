#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/engine.h>

static int hw_get_random_bytes(unsigned char *buf, int num)
{
    int i;
    printf("call hw_get_random_bytes\n");
    for (i = 0; i < num; i++)
        memset(buf++, rand(), 1);
    return 1;
}

/* 生成 RSA 密钥对 */
static int genrete_rsa_key(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    printf("genrete_rsa_key \n");
    return 1;
}
/* RSA 公钥加密 */
int rsa_pub_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    printf("call rsa_pub_enc \n");
    return 1;
}
/*RSA 公钥解密 */
int rsa_pub_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    printf("call rsa_pub_enc \n");
    return 1;
}
/* RSA 私钥加密 */
int rsa_priv_enc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    char *keyid;
    /* 获取私钥 id */
    keyid = (char *)ENGINE_get_ex_data(RSA_get0_engine(rsa), 0);
    printf("call rsa_pub_dec \n");
    printf("use key id :%d \n", keyid);
    return 1;
}
/* RSA 私钥解密 */
int rsa_priv_dec(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    printf("call rsa_priv_dec \n");
    return 1;
}

struct rsa_meth_st {
    char *name;
    int (*rsa_pub_enc) (int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
    int (*rsa_pub_dec) (int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_enc) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_dec) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding);
    /* Can be null */
    int (*rsa_mod_exp) (BIGNUM *r0, const BIGNUM *I, RSA *rsa, BN_CTX *ctx);
    /* Can be null */
    int (*bn_mod_exp) (BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
    /* called at new */
    int (*init) (RSA *rsa);
    /* called at free */
    int (*finish) (RSA *rsa);
    /* RSA_METHOD_FLAG_* things */
    int flags;
    /* may be needed! */
    char *app_data;
    /*
     * New sign and verify functions: some libraries don't allow arbitrary
     * data to be signed/verified: this allows them to be used. Note: for
     * this to work the RSA_public_decrypt() and RSA_private_encrypt() should
     * *NOT* be used RSA_sign(), RSA_verify() should be used instead.
     */
    int (*rsa_sign) (int type,
                     const unsigned char *m, unsigned int m_length,
                     unsigned char *sigret, unsigned int *siglen,
                     const RSA *rsa);
    int (*rsa_verify) (int dtype, const unsigned char *m,
                       unsigned int m_length, const unsigned char *sigbuf,
                       unsigned int siglen, const RSA *rsa);
    /*
     * If this callback is NULL, the builtin software RSA key-gen will be
     * used. This is for behavioural compatibility whilst the code gets
     * rewired, but one day it would be nice to assume there are no such
     * things as "builtin software" implementations.
     */
    int (*rsa_keygen) (RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
    int (*rsa_multi_prime_keygen) (RSA *rsa, int bits, int primes,
                                   BIGNUM *e, BN_GENCB *cb);
};

/* RSA 算法 */
RSA_METHOD hw_rsa =
    {
        "hw cipher",
        rsa_pub_enc,
        rsa_pub_dec,
        rsa_priv_enc,
        rsa_priv_dec,
        NULL,
        NULL,
        NULL,
        NULL,
        RSA_FLAG_THREAD_SAFE,
        NULL,
        NULL,
        NULL,
        genrete_rsa_key,
        NULL
    };

/* 随机数方法 */
static RAND_METHOD hw_rand =
    {
        NULL,
        hw_get_random_bytes,
        NULL,
        NULL,
        NULL,
        NULL,
};

/* Engine 的 id */
static const char *engine_hw_id = "ID_hw";
/* Engine 的名字 */
static const char *engine_hw_name = "hwTest";
static int hw_init(ENGINE *e)
{
    printf("call hw_init\n");
    return 1;
}
static int hw_destroy(ENGINE *e)
{
    printf("call hw_destroy\n");
    return 1;
}

static int hw_finish(ENGINE *e)
{
    printf("call hw_finish\n");
    return 0;
}
static EVP_PKEY *hw_load_privkey(ENGINE *e, const char *key_id,
                                 UI_METHOD *ui_method, void *callback_data)
{
    /* 将密钥 id 放在 ENGINE 的扩展数据中 */
    int index;
    printf("call hw_load_privkey\n");
    index = 0;
    ENGINE_set_ex_data(e, index, (char *)key_id);
    return NULL;
}

#define HW_SET_RSA_PRIVATE_KEY 1
/* 实现自己的控制函数 */
static int hw_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    switch (cmd)
    {
    case HW_SET_RSA_PRIVATE_KEY:
        hw_load_privkey(e, p, NULL, NULL);
        break;
    default:
        printf("err.\n");
        return -1;
    }
    return 0;
}

static EVP_PKEY *hw_load_pubkey(ENGINE *e, const char *key_id,
                                UI_METHOD *ui_method, void *callback_data)
{
    printf("call hw_load_pubkey\n");
    return NULL;
}

static const ENGINE_CMD_DEFN hw_cmd_defns[] = {
    {ENGINE_CMD_BASE,
     "SO_PATH",
     "Specifies the path to the 'hw' shared library",
     ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}};

static int hw_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                       const unsigned char *iv, int enc)
{
    return 1;
}
static int hw_cipher_enc(EVP_CIPHER_CTX *ctx, unsigned char *out,
                         const unsigned char *in, unsigned int inl)
{
    memcpy(out, in, inl);
    return 1;
}

#include <openssl/objects.h>
struct evp_cipher_st {
    int nid;
    int block_size;
    /* Default value for variable length ciphers */
    int key_len;
    int iv_len;
    /* Various flags */
    unsigned long flags;
    /* init key */
    int (*init) (EVP_CIPHER_CTX *ctx, const unsigned char *key,
                 const unsigned char *iv, int enc);
    /* encrypt/decrypt data */
    int (*do_cipher) (EVP_CIPHER_CTX *ctx, unsigned char *out,
                      const unsigned char *in, size_t inl);
    /* cleanup ctx */
    int (*cleanup) (EVP_CIPHER_CTX *);
    /* how big ctx->cipher_data needs to be */
    int ctx_size;
    /* Populate a ASN1_TYPE with parameters */
    int (*set_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Get parameters from a ASN1_TYPE */
    int (*get_asn1_parameters) (EVP_CIPHER_CTX *, ASN1_TYPE *);
    /* Miscellaneous operations */
    int (*ctrl) (EVP_CIPHER_CTX *, int type, int arg, void *ptr);
    /* Application data */
    void *app_data;
} /* EVP_CIPHER */ ;

/* 定义自己的 des_ecb 硬件算法*/
static const EVP_CIPHER EVP_hw_c =
{
        NID_des_ecb,
        1, 8, 0,
        8,
        hw_init_key,
        hw_cipher_enc,
        NULL,
        1,
        NULL,
        NULL,
        NULL,
        NULL
};

const EVP_CIPHER *EVP_hw_cipher(void)
{
    return (&EVP_hw_c);
}

/* 选择对称计算函数 */
static int cipher_nids[] =
    {NID_des_ecb, NID_des_ede3_cbc, 0};

static int hw_ciphers(ENGINE *e, const EVP_CIPHER **cipher, const int **nids, int nid)
{
    if (cipher == NULL)
    {
        *nids = cipher_nids;
        return (sizeof(cipher_nids) - 1) / sizeof(cipher_nids[0]);
    }
    switch (nid)
    {
    case NID_des_ecb:
        *cipher = EVP_hw_cipher();
        break;
        //其他对称函数
    }
    return 1;
}

static int init(EVP_MD_CTX *ctx)
{
    printf("call md init\n");
    return 1;
}
static int update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    printf("call md update\n");
    return 1;
}

static int final(EVP_MD_CTX *ctx, unsigned char *md)
{
    int i;
    printf("call md final\n");
    for (i = 0; i < 20; i++)
        memset(md++, i, 1);
    return 1;
}
int mySign(int type, const unsigned char *m, unsigned int m_length,
           unsigned char *sigret, unsigned int *siglen, void *key)
{
    RSA *k;
    int keyid;
    k = (RSA *)key;
    /* 获取硬件中的私钥 ID，进行计算 */
    keyid = ENGINE_get_ex_data(RSA_get0_engine(k), 0);
    printf("call mySign\n");
    printf("use key id is %d\n", keyid);
    return 1;
}

int myVerify(int type, const unsigned char *m, unsigned int m_length,
             const unsigned char *sigbuf, unsigned int siglen,
             void *key)
{
    printf("call myVerify\n");
    return 1;
}


static int digest_nids[] ={NID_sha1, NID_md5, 0};

struct evp_md_st {
    int type;
    int pkey_type;
    int md_size;
    unsigned long flags;
    int (*init) (EVP_MD_CTX *ctx);
    int (*update) (EVP_MD_CTX *ctx, const void *data, size_t count);
    int (*final) (EVP_MD_CTX *ctx, unsigned char *md);
    int (*copy) (EVP_MD_CTX *to, const EVP_MD_CTX *from);
    int (*cleanup) (EVP_MD_CTX *ctx);
    int block_size;
    int ctx_size;               /* how big does the ctx->md_data need to be */
    /* control function */
    int (*md_ctrl) (EVP_MD_CTX *ctx, int cmd, int p1, void *p2);
} /* EVP_MD */ ;

/* 实现的 sha1 摘要算法 */
static const EVP_MD hw_newmd =
{
        NID_sha1,
        NID_sha1WithRSAEncryption,
        SHA_DIGEST_LENGTH,
        0,
        init,
        update,
        final,
        NULL,
        NULL,
        mySign,   /* sign */
        myVerify, /* verify */
        //sizeof(EVP_MD *)+sizeof(SHA_CTX),
        6
};
static EVP_MD *EVP_hw_md()
{
    return (&hw_newmd);
}
/* 选择摘要算法的函数 */
static int hw_md(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
    if (digest == NULL)

    {
        *nids = digest_nids;
        return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
    }
    switch (nid)
    {
    case NID_sha1:
        *digest = EVP_hw_md();
        break;
        //其他摘要函数
    }
    return 1;
}
static int bind_helper(ENGINE *e)
{
    int ret;
    ret = ENGINE_set_id(e, engine_hw_id);
    if (ret != 1)
    {
        printf("ENGINE_set_id failed\n");
        return 0;
    }
    ret = ENGINE_set_name(e, engine_hw_name);
    if (ret != 1)
    {
        printf("ENGINE_set_name failed\n");
        return 0;
    }
    ret = ENGINE_set_RSA(e, &hw_rsa);
    if (ret != 1)
    {
        printf("ENGINE_set_RSA failed\n");
        return 0;
    }
    ret = ENGINE_set_RAND(e, &hw_rand);
    if (ret != 1)
    {
        printf("ENGINE_set_RAND failed\n");
        return 0;
    }
    ret = ENGINE_set_destroy_function(e, hw_destroy);
    if (ret != 1)
    {
        printf("ENGINE_set_destroy_function failed\n");
        return 0;
    }
    ret = ENGINE_set_init_function(e, hw_init);
    if (ret != 1)
    {
        printf("ENGINE_set_init_function failed\n");
        return 0;
    }
    ret = ENGINE_set_finish_function(e, hw_finish);
    if (ret != 1)
    {
        printf("ENGINE_set_finish_function failed\n");
        return 0;
    }
    ret = ENGINE_set_ctrl_function(e, hw_ctrl);
    if (ret != 1)
    {
        printf("ENGINE_set_ctrl_function failed\n");
        return 0;
    }
    ret = ENGINE_set_load_privkey_function(e, hw_load_privkey);
    if (ret != 1)
    {
        printf("ENGINE_set_load_privkey_function failed\n");
        return 0;
    }
    ret = ENGINE_set_load_pubkey_function(e, hw_load_pubkey);
    if (ret != 1)
    {
        printf("ENGINE_set_load_pubkey_function failed\n");
        return 0;
    }
    ret = ENGINE_set_cmd_defns(e, hw_cmd_defns);
    if (ret != 1)
    {
        printf("ENGINE_set_cmd_defns failed\n");
        return 0;
    }
    ret = ENGINE_set_ciphers(e, hw_ciphers);
    if (ret != 1)
    {
        printf("ENGINE_set_ciphers failed\n");
        return 0;
    }
    ret = ENGINE_set_digests(e, hw_md);
    if (ret != 1)
    {
        printf("ENGINE_set_digests failed\n");
        return 0;
    }
    return 1;
}
static ENGINE *engine_hwcipher(void)
{
    ENGINE *ret = ENGINE_new();
    if (!ret)
        return NULL;
    if (!bind_helper(ret))
    {
        ENGINE_free(ret);
        return NULL;
    }
    return ret;
}
void ENGINE_load_hwcipher()
{
    ENGINE *e_hw = engine_hwcipher();
    if (!e_hw)
        return;
    ENGINE_add(e_hw);
    ENGINE_free(e_hw);
    ERR_clear_error();
}
#define HW_set_private_keyID(a) func(e, a, 0, (void *)1, NULL)
#include <openssl/engine.h>
#include <openssl/evp.h>
int main()
{
    ENGINE *e;
    RSA_METHOD *meth;
    int ret, num = 20, i;
    char buf[20], *name;
    EVP_CIPHER *cipher;
    EVP_MD *md;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    EVP_CIPHER_CTX* ciph_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX* dciph_ctx = EVP_CIPHER_CTX_new();
    unsigned char key[8], iv[8];
    unsigned char in[50], out[256] = {0}, dd[60] = {0};
    int inl, outl, total, dtotal;
    RSA *rkey;
    RSA_METHOD *rsa_m;
    EVP_PKEY *ek, *pkey;
    ENGINE_CTRL_FUNC_PTR func;
    char err_string[1024] = {0};
    ERR_load_ENGINE_strings();
    OpenSSL_add_all_algorithms();
    ENGINE_load_hwcipher();
    e = ENGINE_by_id("ID_hw");
    name = (char *)ENGINE_get_name(e);
    printf("engine name :%s \n", name);
    /* 随机数生成 */
    ret = RAND_set_rand_engine(e);
    if (ret != 1)
    {
        printf("RAND_set_rand_engine err\n");
        return -1;
    }
    ret = ENGINE_set_default_RAND(e);
    if (ret != 1)
    {
        printf("ENGINE_set_default_RAND err\n");
        return -1;
    }
    ret = RAND_bytes((unsigned char *)buf, num);
    /* 对称加密 */
    for (i = 0; i < 8; i++)
        memset(&key[i], i, 1);
    EVP_CIPHER_CTX_init(ciph_ctx);
    /* 采用 Engine 对称算法 */
    cipher = EVP_des_ecb();
    ret = EVP_EncryptInit_ex(ciph_ctx, cipher, e, key, iv);
    if (ret != 1)
    {
        printf("EVP_EncryptInit_ex err\n");
        return -1;
    }
    strcpy((char *)in, "zcpsssssssssssss");
    inl = strlen((const char *)in);
    total = 0;
    ret = EVP_EncryptUpdate(ciph_ctx, out, &outl, in, inl);
    if (ret != 1)
    {
        printf("EVP_EncryptUpdate err\n");
        return -1;
    }
    total += outl;
    ret = EVP_EncryptFinal(ciph_ctx, out + total, &outl);
    if (ret != 1)
    {
        printf("EVP_EncryptFinal err\n");
        return -1;
    }
    total += outl;
    /* 解密 */
    dtotal = 0;
    EVP_CIPHER_CTX_init(dciph_ctx);
    ret = EVP_DecryptInit_ex(dciph_ctx, cipher, e, key, iv);
    if (ret != 1)
    {
        printf("EVP_DecryptInit_ex err\n");
        return -1;
    }
    
    ret = EVP_DecryptUpdate(dciph_ctx, dd, &outl, out, total);
    if (ret != 1)
    {
        printf("EVP_DecryptUpdate err\n");
        return -1;
    }
    dtotal += outl;
    ret = EVP_DecryptFinal(dciph_ctx, dd + dtotal, &outl);
    if (ret != 1)
    {
        printf("EVP_DecryptFinal err\n");
        return -1;
    }
    dtotal += outl;
    /* Engine 摘要 */
    EVP_MD_CTX_init(mctx);
    md = EVP_sha1();
    ret = EVP_DigestInit_ex(mctx, md, e);
    if (ret != 1)
    {
        printf("EVP_DigestInit_ex err.\n");
        ERR_error_string(ERR_get_error(), err_string);
        printf("EVP_DigestInit_ex fail: %s\n", err_string);
        return -1;
    }
    ret = EVP_DigestUpdate(mctx, in, inl);
    if (ret != 1)
    {
        printf("EVP_DigestUpdate err.\n");
        return -1;
    }
    ret = EVP_DigestFinal(mctx, out, (unsigned int *)&outl);
    if (ret != 1)
    {
        printf("EVP_DigestFinal err.\n");
        return -1;
    }
    
    func = ENGINE_get_ctrl_function(e);
    /* 设置计算私钥 ID */
    HW_set_private_keyID(1);
#if 0
    rkey = RSA_new_method(e);
#else
    rkey = RSA_new();
    BIGNUM* bne = BN_new();
    BN_set_word(bne, RSA_3);
    RSA_generate_key_ex(rkey, 512, bne, NULL);
#endif

    BIO* sout = BIO_new_fp(stdout, BIO_NOCLOSE);
    RSA_print(sout,rkey, 0);

    pkey = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pkey, rkey);
    EVP_MD_CTX_init(md_ctx);
    ret = EVP_SignInit_ex(md_ctx, EVP_sha1(), e);
    if (ret != 1)
    {
        printf("EVP_SignInit_ex err\n");
        return -1;
    }
    ret = EVP_SignUpdate(md_ctx, in, inl);
    if (ret != 1)
    {
        printf("EVP_SignUpdate err\n");
        return -1;
    }
    printf("======================>\n");
    ret = EVP_SignFinal(md_ctx, out, (unsigned int *)&outl, pkey);
    if (ret != 1)
    {
        printf("EVP_SignFinal err\n");
        return -1;
    }
    printf("<======================\n");

    /* 私钥加密 */
    RSA_private_encrypt(inl, in, out, rkey, 1);
    /* 公钥解密 */
    /* 公钥加密 */
    /* 私钥解密 */
    printf("all test ok.\n");
    EVP_MD_CTX_free(mctx);
    EVP_MD_CTX_free(md_ctx);
    EVP_CIPHER_CTX_free(dciph_ctx);
    EVP_CIPHER_CTX_free(ciph_ctx);
    ENGINE_free(e);
    ENGINE_finish(e);
    return 0;
}
