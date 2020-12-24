#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

void print_bin(unsigned char* tag ,unsigned char* data, int len)
{
    printf("%s: ", tag);
    for(int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");

}

class evp_md
{
private:
    const EVP_MD* md;
    EVP_MD_CTX* ctx;
    char err_string[1024];
public:
    evp_md(const EVP_MD* digest): md(digest)
    {
        memset(err_string, 0, 1024);
        ERR_load_EVP_strings();
        EVP_add_digest(digest);
        ctx = EVP_MD_CTX_new();
        EVP_MD_CTX_init(ctx);
        if(!EVP_DigestInit_ex(ctx, md, NULL))
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp digest init fail: %s\n", err_string);
        }
    }

    int evp_digest_update(char* in, int inlen)
    {
        printf("--------------------------------------------\n");
        int ret = 0;
        ret = EVP_DigestUpdate(ctx, in, inlen);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp digest update fail: %s\n", err_string);
        }
        return ret;
    }

    int evp_digest_final(unsigned char* out, unsigned int* outlen)
    {
        int ret = 0;
        ret = EVP_DigestFinal_ex(ctx, out, outlen);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp digest final fail: %s\n", err_string);
        }
        return ret;
    }

    void evp_digest_info()
    {
        printf("--------------------------------------------\n");
        //信息摘要结构算法的NID
        printf("md name:\t%s\n", OBJ_nid2ln(EVP_MD_type(md)));
        printf("md nid:\t\t%d\n", EVP_MD_type(md));
        //返回结构里面摘要信息的长度
        printf("md size:\t%d\n", EVP_MD_size(md));
        //返回摘要信息分块的长度
        printf("md block size:\t%d\n", EVP_MD_block_size(md));
    }

    int evp_digest(char* in, int inlen, unsigned char* out, unsigned int *outlen)
    {
        int ret = EVP_Digest(in, inlen, out, outlen, md, NULL);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp digest fail: %s\n", err_string);
        }
        return ret;
    }
    ~evp_md()
    {
        EVP_MD_CTX_free(ctx);
        EVP_cleanup();
    }
};

void digest()
{
    char* in = "hello world";
    int inlen = strlen(in);
    unsigned char out[128] = {0};
    unsigned int outlen = 128; 
#if 1
    printf("====================================================\n");
    evp_md* md = new evp_md(EVP_md_null());
    md->evp_digest_info();
    md->evp_digest_update(in, inlen);
    md->evp_digest_final(out, &outlen);
    print_bin("md null", out, outlen);
    delete md;
    memset(out, 0 ,128);
#endif

    printf("====================================================\n");
    evp_md* md_sha256 = new evp_md(EVP_sha256());
    md_sha256->evp_digest_info();
    md_sha256->evp_digest_update(in, inlen);
    md_sha256->evp_digest_final(out, &outlen);
    print_bin("sha256", out, outlen);
    delete md_sha256;
    memset(out, 0 ,128);

    printf("====================================================\n");
    evp_md* md_md5 = new evp_md(EVP_md5());
    md_md5->evp_digest_info();
    md_md5->evp_digest_update(in, inlen);
    md_md5->evp_digest_final(out, &outlen);
    print_bin("md5", out, outlen);
    delete md_md5;
    memset(out, 0 ,128);

    printf("====================================================\n");
    md_sha256 = new evp_md(EVP_get_digestbyname("sha256"));
    md_sha256->evp_digest_info();
    md_sha256->evp_digest_update(in, inlen);
    md_sha256->evp_digest_final(out, &outlen);
    print_bin("sha256", out, outlen);
    delete md_sha256;
    memset(out, 0 ,128);

    printf("====================================================\n");
    md_md5 = new evp_md(EVP_get_digestbynid(4));
    md_md5->evp_digest_info();
    md_md5->evp_digest_update(in, inlen);
    md_md5->evp_digest_final(out, &outlen);
    print_bin("md5", out, outlen);
    delete md_md5;
    memset(out, 0 ,128);
    
    printf("====================================================\n");
    md = new evp_md(EVP_blake2b512());
    md->evp_digest_info();
    md->evp_digest(in, inlen, out, &outlen);
    print_bin("blake2b512", out, outlen);
    delete md_md5;
    memset(out, 0 ,128);

}

//==============================================================================
// 对称加解密
class evp_cipher
{
private:
    const EVP_CIPHER *cipher;
    int enc;
    const unsigned char *aKey;
    const unsigned char *iVec;
    EVP_CIPHER_CTX* ctx;
    char err_string[1024];
public:
    evp_cipher(const EVP_CIPHER *c,int enc, const unsigned char* key, const unsigned char *vec):cipher(c), enc(enc),aKey(key), iVec(vec)
    {
        int ret; 
        memset(err_string, 0, 1024);
        ERR_load_EVP_strings();
        EVP_add_cipher(cipher);
        ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(ctx);
        ret = EVP_CipherInit_ex(ctx, cipher, NULL, aKey, iVec, enc);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp cipher init fail: %s\n", err_string);
        }
    }

    int evp_cipher_update(const unsigned char* in, int inlen, unsigned char* out, int* outlen)
    {
        //printf("--------------------------------------------\n");
        int ret = 0;
        ret = EVP_CipherUpdate(ctx, out, outlen, in, inlen);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp cipher update fail: %s\n", err_string);
        }
        return ret;
    }

    int evp_cipher_final(unsigned char* out, int* outlen)
    {
        int ret = 0;
        ret = EVP_CipherFinal_ex(ctx, out, outlen);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp cipher final fail: %s\n", err_string);
        }
        return ret;
    }

    void evp_cipher_info()
    {
        printf("--------------------------------------------\n");
        printf("cipher name:\t\t%s\n", OBJ_nid2ln(EVP_CIPHER_nid(cipher)));
        printf("cipher nid:\t\t%d\n", EVP_CIPHER_nid(cipher));
        printf("cipher block size:\t%d\n", EVP_CIPHER_block_size(cipher));
        printf("cipher key size:\t%d\n", EVP_CIPHER_key_length(cipher));
        printf("cipher iv size:\t\t%d\n", EVP_CIPHER_iv_length(cipher));
        switch(EVP_CIPHER_mode(cipher))
        {
            case EVP_CIPH_ECB_MODE:
                printf("cipher mode:\t\tEVP_CIPH_ECB_MODE\n");
                break;
            case EVP_CIPH_CBC_MODE:
                printf("cipher mode:\t\tEVP_CIPH_CBC_MODE\n");
                break;
            case EVP_CIPH_CFB_MODE:
                printf("cipher mode:\t\tEVP_CIPH_CFB_MODE\n");
                break;
            case EVP_CIPH_OFB_MODE:
                printf("cipher mode:\t\tEVP_CIPH_OFB_MODE\n");
                break;
            case EVP_CIPH_CTR_MODE:
                printf("cipher mode:\t\tEVP_CIPH_CTR_MODE\n");
                break;
            case EVP_CIPH_GCM_MODE:
                printf("cipher mode:\t\tEVP_CIPH_GCM_MODE\n");
                break;
            case EVP_CIPH_CCM_MODE:
                printf("cipher mode:\t\tEVP_CIPH_CCM_MODE\n");
                break;
            case EVP_CIPH_XTS_MODE:
                printf("cipher mode:\t\tEVP_CIPH_XTS_MODE\n");
                break;
            case EVP_CIPH_WRAP_MODE:
                printf("cipher mode:\t\tEVP_CIPH_WRAP_MODE\n");
                break;
            case EVP_CIPH_OCB_MODE:
                printf("cipher mode:\t\tEVP_CIPH_OCB_MODE\n");
                break;
            case EVP_CIPH_MODE:
                printf("cipher mode:\t\tEVP_CIPH_MODE\n");
                break;
            defualt:
                printf("cipher mode:\t\tunknow\n");
                break;
        }
    }

    void evp_reset()
    {
        EVP_CIPHER_CTX_reset(ctx);
    }

    ~evp_cipher()
    {
        EVP_CIPHER_CTX_free(ctx);
        EVP_cleanup();
    }
};

void cipher()
{
    unsigned char key[EVP_MAX_KEY_LENGTH] = {0};
    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};
    unsigned char* in = "hello world\n";
    int inlen = strlen(in);
    unsigned char out[inlen*2 + EVP_MAX_BLOCK_LENGTH] = {0};
    int outlen = inlen*2 + EVP_MAX_BLOCK_LENGTH;
    unsigned char d[64] = {0};
    unsigned int dlen = 64;

    char* passwd = "111111";
    int count = 3; //count is the iteration count to use

    unsigned char* tmp = out;
    int tmplen = outlen;
    //从输入密码产生了密钥key和初始化向量iv
    EVP_BytesToKey(EVP_des_cbc(), EVP_md5(), NULL, passwd, strlen(passwd), count, key, iv);

    evp_cipher* encrypt = new evp_cipher(EVP_des_cbc(), 1, key, iv);
    encrypt->evp_cipher_info();
    encrypt->evp_cipher_update(in, inlen, tmp, &tmplen);
    tmp += tmplen;
    outlen -= tmplen;
    tmplen = outlen;
    encrypt->evp_cipher_update(in, inlen, tmp, &tmplen);
    tmp += tmplen;
    outlen -= tmplen;
    tmplen = outlen;
    encrypt->evp_cipher_final(tmp, &tmplen);
    outlen -= tmplen;
    outlen = inlen*2 + EVP_MAX_BLOCK_LENGTH - outlen;
    print_bin("enc data", out, outlen);


//================================================================================
    //printf("-------------------------------------------------------------------------\n");
    evp_cipher* decrypt = new evp_cipher(EVP_des_cbc(), 0, key, iv);
    decrypt->evp_cipher_info();
    //decrypt->evp_decrypt(out, outlen, d);
    decrypt->evp_cipher_update(out, outlen, d, &dlen);
    printf("%s\n", d);
    //printf("-------------------------------------------------------------------------\n");

    encrypt->evp_reset();
    decrypt->evp_reset();
    delete encrypt;
    delete decrypt;
}

class evp_crypto
{
private:
    EVP_CIPHER_CTX *en_ctx;
    EVP_CIPHER_CTX *de_ctx;
    const EVP_CIPHER *cipher;
    char err_string[1024];
public:
    evp_crypto( const EVP_CIPHER *c, const unsigned char *key, const unsigned char *iv):cipher(c)
    {
        int ret; 
        memset(err_string, 0, 1024);
        ERR_load_EVP_strings();
        EVP_add_cipher(cipher);

        en_ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(en_ctx);
        de_ctx = EVP_CIPHER_CTX_new();
        EVP_CIPHER_CTX_init(de_ctx);

        ret = EVP_EncryptInit_ex(en_ctx, cipher, NULL, key, iv);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp Encrypt init fail: %s\n", err_string);
        }
        
        ret = EVP_DecryptInit_ex(de_ctx, cipher, NULL, key, iv);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp Decrypt init fail: %s\n", err_string);
        }       
    }
    void evp_crypto_info()
    {
        printf("--------------------------------------------\n");
        printf("cipher name:\t\t%s\n", OBJ_nid2ln(EVP_CIPHER_nid(cipher)));
        printf("cipher nid:\t\t%d\n", EVP_CIPHER_nid(cipher));
        printf("cipher block size:\t%d\n", EVP_CIPHER_block_size(cipher));
        printf("cipher key size:\t%d\n", EVP_CIPHER_key_length(cipher));
        printf("cipher iv size:\t\t%d\n", EVP_CIPHER_iv_length(cipher));
        switch(EVP_CIPHER_mode(cipher))
        {
            case EVP_CIPH_ECB_MODE:
                printf("cipher mode:\t\tEVP_CIPH_ECB_MODE\n");
                break;
            case EVP_CIPH_CBC_MODE:
                printf("cipher mode:\t\tEVP_CIPH_CBC_MODE\n");
                break;
            case EVP_CIPH_CFB_MODE:
                printf("cipher mode:\t\tEVP_CIPH_CFB_MODE\n");
                break;
            case EVP_CIPH_OFB_MODE:
                printf("cipher mode:\t\tEVP_CIPH_OFB_MODE\n");
                break;
            case EVP_CIPH_CTR_MODE:
                printf("cipher mode:\t\tEVP_CIPH_CTR_MODE\n");
                break;
            case EVP_CIPH_GCM_MODE:
                printf("cipher mode:\t\tEVP_CIPH_GCM_MODE\n");
                break;
            case EVP_CIPH_CCM_MODE:
                printf("cipher mode:\t\tEVP_CIPH_CCM_MODE\n");
                break;
            case EVP_CIPH_XTS_MODE:
                printf("cipher mode:\t\tEVP_CIPH_XTS_MODE\n");
                break;
            case EVP_CIPH_WRAP_MODE:
                printf("cipher mode:\t\tEVP_CIPH_WRAP_MODE\n");
                break;
            case EVP_CIPH_OCB_MODE:
                printf("cipher mode:\t\tEVP_CIPH_OCB_MODE\n");
                break;
            case EVP_CIPH_MODE:
                printf("cipher mode:\t\tEVP_CIPH_MODE\n");
                break;
            defualt:
                printf("cipher mode:\t\tunknow\n");
                break;
        }
    }

    int evp_encrypt_update(const unsigned char *in, int inlen, unsigned char *out, int *outlen)
    {
        int ret = 0;
        ret = EVP_EncryptUpdate(en_ctx, out, outlen, in, inlen);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp encrypt update fail: %s\n", err_string);
        }
        return ret;
    }

    int evp_encrypt_final(unsigned char* out, int* outlen)
    {
        int ret = 0;
        ret = EVP_EncryptFinal_ex(en_ctx, out, outlen);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp encrypt final fail: %s\n", err_string);
        }
        return ret;
    }

    int evp_decrypt_update(const unsigned char *in, int inlen, unsigned char *out, int *outlen)
    {
        int ret = 0;
        ret = EVP_DecryptUpdate(de_ctx, out, outlen, in, inlen);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp encrypt update fail: %s\n", err_string);
        }
        return ret;
    }


    int evp_decrypt_final(unsigned char* out, int* outlen)
    {
        int ret = 0;
        ret = EVP_DecryptFinal_ex(de_ctx, out, outlen);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp decrypt final fail: %s\n", err_string);
        }
        return ret;
    }

    ~evp_crypto()
    {
        EVP_CIPHER_CTX_free(en_ctx);
        EVP_CIPHER_CTX_free(de_ctx);
        EVP_cleanup();
    }
};


void crypto()
{
    unsigned char key[EVP_MAX_KEY_LENGTH] = {0};
    unsigned char iv[EVP_MAX_IV_LENGTH] = {0};
    unsigned char* in = "hello world";
    int inlen = strlen(in);
    unsigned char out[inlen + EVP_MAX_BLOCK_LENGTH] = {0};
    int outlen = sizeof(out);
    unsigned char d[inlen] = {0};
    unsigned int dlen = sizeof(d);

    char* passwd = "11111111";
    int count = 3; //count is the iteration count to use

    unsigned char* tmp = out;
    int datalen = 0;

    const EVP_CIPHER* cipher = EVP_aes_256_ofb();
    //从输入密码产生了密钥key和初始化向量iv
    EVP_BytesToKey(cipher, EVP_md5(), NULL, passwd, strlen(passwd), count, key, iv);

    evp_crypto* crypto = new evp_crypto(cipher, key, iv);
    crypto->evp_crypto_info();
    crypto->evp_encrypt_update(in, inlen, tmp, &outlen);
    datalen += outlen;
    crypto->evp_encrypt_final(tmp+outlen, &outlen);
    datalen += outlen;
    print_bin("enc data", out, datalen);
    printf("-------------------------------------------------------\n");

    tmp = d;
    crypto->evp_decrypt_update(out, datalen, d, &dlen);
    tmp += dlen;
    dlen = sizeof(d) - dlen;
    crypto->evp_decrypt_final(tmp, &dlen);
    tmp += dlen;
    dlen = tmp - d;
    printf("dec data len: %d\n", dlen);
    printf("dec data:");
    for(int i = 0; i < dlen; i++)
    {
        printf("%c", d[i]);
    }
    printf("\n");


    

}

// 非对称加解密
class evp_pkey_encrypt
{
private:
    EVP_PKEY *pkey;
    EVP_PKEY_CTX* ctx;
    char err_string[1024];
public:
    evp_pkey_encrypt(EVP_PKEY * key):pkey(key)
    {
        int ret; 
        memset(err_string, 0, 1024);
        ERR_load_EVP_strings();
        EVP_add_alg_module();
        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        ret = EVP_PKEY_encrypt_init(ctx);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp pkey encrypt init fail: %s\n", err_string);
        }
    }

    int encrypt(const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen)
    {
        int ret = EVP_PKEY_encrypt(ctx, out, outlen, in, inlen);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp pkey encrypt init fail: %s\n", err_string);
        }
        return ret;
    }
    
    void evp_pkey_encrypt_info()
    {
        printf("PKEY name:\t%s\n", OBJ_nid2ln(EVP_PKEY_type(EVP_PKEY_base_id(pkey))));
        printf("PKEY size:\t%d\n", EVP_PKEY_size(pkey));
        printf("PKEY bits:\t%d\n", EVP_PKEY_bits(pkey));
    }
    ~evp_pkey_encrypt()
    {
        EVP_PKEY_CTX_free(ctx);
    }
};


class evp_pkey_decrypt
{
private:
    EVP_PKEY *pkey;
    EVP_PKEY_CTX* ctx;
    char err_string[1024];
public:
    evp_pkey_decrypt(EVP_PKEY * key):pkey(key)
    {
        int ret; 
        memset(err_string, 0, 1024);
        ERR_load_EVP_strings();
        EVP_add_alg_module();
        ctx = EVP_PKEY_CTX_new(pkey, NULL);
        ret = EVP_PKEY_decrypt_init(ctx);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp pkey decrypt init fail: %s\n", err_string);
        }
    }

    int decrypt(const unsigned char *in, size_t inlen, unsigned char *out, size_t *outlen)
    {
        int ret = EVP_PKEY_decrypt(ctx, out, outlen, in, inlen);
        if(!ret)
        {
            ERR_error_string(ERR_get_error(), err_string);
            printf("evp pkey decrypt init fail: %s\n", err_string);
        }
        return ret;
    }
    
    void evp_pkey_decrypt_info()
    {
        printf("PKEY name:\t%s\n", OBJ_nid2ln(EVP_PKEY_type(EVP_PKEY_base_id(pkey))));
        printf("PKEY size:\t%d\n", EVP_PKEY_size(pkey));
        printf("PKEY bits:\t%d\n", EVP_PKEY_bits(pkey));
    }
    ~evp_pkey_decrypt()
    {
        EVP_PKEY_CTX_free(ctx);
    }
};

void pkey_rsa()
{
    BIGNUM* bne;
    RSA* rsaParis;
    RSA* rsaPublic;
    RSA* rsaPrivate;
    EVP_PKEY* pub;
    EVP_PKEY* pri;
    char* in = "hello world";
    size_t inlen = strlen(in);
    unsigned char* out;
    size_t outlen = 0;
    unsigned char* data;
    size_t datalen;
    rsaParis = RSA_new();
    bne = BN_new();
    BN_set_word(bne, RSA_3);
    RSA_generate_key_ex(rsaParis, 1024, bne, NULL);
    rsaPublic = RSAPublicKey_dup(rsaParis);
    rsaPrivate = RSAPrivateKey_dup(rsaParis);

    pub = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pub, rsaPublic);

    pri = EVP_PKEY_new();
    EVP_PKEY_set1_RSA(pri, rsaPrivate);

    evp_pkey_encrypt* e = new evp_pkey_encrypt(pub);
    evp_pkey_decrypt* d = new evp_pkey_decrypt(pri);
    e->evp_pkey_encrypt_info();
    //=================================

    e->encrypt((const unsigned char*)in, inlen, NULL, &outlen);
    out = (unsigned char*)OPENSSL_zalloc(sizeof(unsigned char)*outlen);
    e->encrypt((const unsigned char*)in, inlen, out, &outlen);
    print_bin("enc data", out, outlen);

    printf("------------------------------------------------------------\n");
    d->evp_pkey_decrypt_info();
    d->decrypt(out, outlen, NULL, &datalen);
    data = (unsigned char*)OPENSSL_zalloc(sizeof(unsigned char)*datalen);
    d->decrypt(out, outlen, data, &datalen);
    printf("%d:%s\n", datalen, data);

    RSA_free(rsaParis);
    RSA_free(rsaPublic);
    RSA_free(rsaPrivate);
    BN_free(bne);
    EVP_PKEY_free(pub);
    EVP_PKEY_free(pri);
    OPENSSL_free(out);
    delete e;
    delete d;
}

void pkey()
{
    pkey_rsa();
}

int main(int argc, char const *argv[])
{
    // 摘要
    //digest();
    printf("====================================================\n");
    // 对称解密
    //cipher();
    printf("====================================================\n");
    // 对称加解密
    //crypto();
    printf("====================================================\n");
    // 非对称加解密
    pkey();

    return 0;
}
