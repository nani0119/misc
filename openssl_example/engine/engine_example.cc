#include <stdlib.h>
#include <string.h>

#include <openssl/engine.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/modes.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

// engine/eng_openssl.c

static const char *engine_id = "hw_engine";
static const char *engine_name = "hw engine example";

void print_bin(unsigned char* tag ,unsigned char* data, int len)
{
    printf("%s: ", tag);
    for(int i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");

}

//========================================================================
static int hw_get_random_bytes(unsigned char *buf, int num)
{
    int i;
    printf("call hw_get_random_bytes\n");
    for (i = 0; i < num; i++)
        memset(buf++, rand() % 255, 1);
    return 1;
}
/* 随机数方法 */
static RAND_METHOD hw_engine_rand ={
    NULL,
    hw_get_random_bytes,
    NULL,
    NULL,
    NULL,
    NULL,
};
//======================================================================
/** SHA1 implementation */
static int hw_engine_sha1_init(EVP_MD_CTX* ctx)
{
    printf("------------%s---------------\n", __func__);
    SHA1_Init((SHA_CTX*)EVP_MD_CTX_md_data(ctx));
    return 1;
}

static int hw_engine_sha1_update(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    printf("------------%s---------------\n", __func__);
    SHA1_Update((SHA_CTX*)EVP_MD_CTX_md_data(ctx), data, count);
    return 1;
}

static int hw_engine_sha1_final(EVP_MD_CTX *ctx, unsigned char *md)
{
    printf("------------%s---------------\n", __func__);
    SHA1_Final(md, (SHA_CTX*)EVP_MD_CTX_md_data(ctx));
    return 1;
}

static EVP_MD *hw_engine_sha1 = NULL;
static EVP_MD *hw_engine_digest_sha1()
{
    printf("------------%s---------------\n", __func__);
    if (hw_engine_sha1 == NULL)
    {
        EVP_MD *md;

        if ((md = EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption)) == NULL 
                || !EVP_MD_meth_set_result_size(md, SHA_DIGEST_LENGTH) 
                || !EVP_MD_meth_set_input_blocksize(md, SHA_CBLOCK) 
                || !EVP_MD_meth_set_app_datasize(md, sizeof(EVP_MD *) + sizeof(SHA_CTX)) 
                || !EVP_MD_meth_set_flags(md, 0) 
                || !EVP_MD_meth_set_init(md, hw_engine_sha1_init) 
                || !EVP_MD_meth_set_update(md, hw_engine_sha1_update) 
                || !EVP_MD_meth_set_final(md, hw_engine_sha1_final))
        {
            EVP_MD_meth_free(md);
            md = NULL;
        }
        hw_engine_sha1 = md;
    }
    return hw_engine_sha1;
}


static void hw_engine_sha1_destroy()
{
    EVP_MD_meth_free(hw_engine_sha1);
    hw_engine_sha1 = NULL;
}

static int digest_nids[] = {NID_sha1, 0};

int digest_selector(ENGINE *e, const EVP_MD **digest, const int **nids, int nid)
{
    int ok = 1;
    printf("------------%s---------------\n", __func__);
    if (!digest)
    {
        /* expected to return the list of supported NIDs */
        *nids = digest_nids;
        return (sizeof(digest_nids) - 1) / sizeof(digest_nids[0]);
    }

    /** Request for a specific digest */
    switch (nid)
    {
    case NID_sha1:
        *digest = hw_engine_digest_sha1();
        break;
    default:
        ok = 0;
        *digest = NULL;
        break;
    }
    return ok;
}
//=================================================================

static int hw_engine_init(ENGINE *e)
{
    printf("------------%s---------------\n", __func__);
    return 1;
}

static int hw_engine_destroy(ENGINE *e)
{
    printf("------------%s---------------\n", __func__);
    hw_engine_sha1_destroy();
    return 1;
}

static int hw_engine_finish(ENGINE *e)
{
    printf("------------%s---------------\n", __func__);
    return 0;
}

static EVP_PKEY *hw_engine_load_privkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data)
{
    /* 将密钥 id 放在 ENGINE 的扩展数据中 */
    printf("------------%s---------------\n", __func__);
    return NULL;
}

static EVP_PKEY *hw_engine_load_pubkey(ENGINE *e, const char *key_id, UI_METHOD *ui_method, void *callback_data)
{
    printf("------------%s---------------\n", __func__);
    return NULL;
}

#define HW_SET_RSA_PRIVATE_KEY 1
/* 实现自己的控制函数 */
static int hw_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
    switch (cmd)
    {
    case HW_SET_RSA_PRIVATE_KEY:
        hw_engine_load_pubkey(e, p, NULL, NULL);
        break;
    default:
        printf("err.\n");
        return -1;
    }
    return 0;
}

static const ENGINE_CMD_DEFN hw_engine_cmd_defns[] = {
    {ENGINE_CMD_BASE, "SO_PATH", "Specifies the path to the 'hw' shared library", ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

static int bind_engine_helper(ENGINE *e, const char *id)
{
    int ret = 0;
    printf("------------%s---------------\n", __func__);
    if (!ENGINE_set_id(e, id))
    {
        printf("ENGINE_set_id failed\n");
        goto end;
    }

    if (!ENGINE_set_name(e, engine_name))
    {
        printf("ENGINE_set_name failed\n");
        goto end;
    }

    if (!ENGINE_set_destroy_function(e, hw_engine_destroy))
    {
        printf("ENGINE_set_destroy_function failed\n");
        goto end;
    }

    if (!ENGINE_set_init_function(e, hw_engine_init))
    {
        printf("ENGINE_set_init_function failed\n");
        goto end;
    }

    if (!ENGINE_set_finish_function(e, hw_engine_finish))
    {
        printf("ENGINE_set_finish_function failed\n");
        goto end;
    }

    if (!ENGINE_set_ctrl_function(e, hw_engine_ctrl))
    {
        printf("ENGINE_set_ctrl_function failed\n");
        goto end;
    }

    if (!ENGINE_set_load_privkey_function(e, hw_engine_load_privkey))
    {
        printf("ENGINE_set_load_privkey_function failed\n");
        goto end;
    }

    if (!ENGINE_set_load_pubkey_function(e, hw_engine_load_pubkey))
    {
        printf("ENGINE_set_load_pubkey_function failed\n");
        goto end;
    }

    if (!ENGINE_set_cmd_defns(e, hw_engine_cmd_defns))
    {
        printf("ENGINE_set_cmd_defns failed\n");
        goto end;
    }

    if (!ENGINE_set_digests(e, digest_selector))
    {
        printf("ENGINE_set_digest failed\n");
        goto end;
    }

    if (!ENGINE_set_RAND(e, &hw_engine_rand))
    {
        printf("ENGINE_set_digest failed\n");
        goto end;
    }
    
    ret = 1;
end:
    return ret;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_engine_helper)


static ENGINE *hw_engine(void)
{
    ENGINE *e = ENGINE_new();
    printf("------------%s---------------\n", __func__);
    if (!e)
        return NULL;
    if (!bind_engine_helper(e, engine_id))
    {
        ENGINE_free(e);
        return NULL;
    }
    return e;
}

void load_hw_engine()
{
    ENGINE *e_hw = hw_engine();
    printf("------------%s---------------\n", __func__);
    if (!e_hw)
        return;
    ENGINE_add(e_hw);
    ENGINE_free(e_hw);
    ERR_clear_error();
}

int main(int argc, char const *argv[])
{
    ENGINE* e = NULL;
    char* in = "hello world";
    int inlen = strlen(in);
    unsigned char out[128] = {0};
    unsigned int outlen = 128;
    char* name;
    OpenSSL_add_all_algorithms();
    load_hw_engine();
    e = ENGINE_by_id(engine_id);
    if(e == NULL)
    {
        printf("failed to retrieve engine by id :%s\n", engine_id);
        return 1;
    }

    name = (char *)ENGINE_get_name(e);
    printf("engine name :%s \n",name);
    //===========================================================
    const EVP_MD* md = EVP_sha1();
    EVP_add_digest(EVP_sha1());
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_MD_CTX_init(ctx);
    EVP_DigestInit_ex(ctx, md, e);
    EVP_DigestUpdate(ctx, in, inlen);
    EVP_DigestFinal_ex(ctx, out, &outlen);
    print_bin("sha1",out, outlen);
    EVP_MD_CTX_free(ctx);

    //===============================================================
    ENGINE_finish(e);
    return 0;
}
