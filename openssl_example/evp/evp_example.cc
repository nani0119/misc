#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

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


int main(int argc, char const *argv[])
{
    digest();
    printf("====================================================\n");
    return 0;
}
