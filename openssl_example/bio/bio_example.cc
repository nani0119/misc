#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>


void test_mem_bio()
{
    BIO*  b = NULL;
    int   len = 0;
    char* out = NULL;
    char* in = "test mem bio";
    printf("===============================================\n");

    b = BIO_new(BIO_s_mem());
    printf("method name:%s\n", BIO_method_name(b));
    printf("method type:%04x\n",BIO_method_type(b));

    len = BIO_write(b, in, strlen(in));
    printf("BIO_write: %d:%s\n", len, in);

    in = "openssl";
    len = BIO_printf(b, in, strlen(in));
    printf("BIO_printf: %d:%s\n", len, in);

    len = BIO_ctrl_pending(b);
    printf("total len:%d\n", len);

    out=(char *)OPENSSL_zalloc(len);
    len = BIO_read(b, out, len/2);
    printf("BIO_read:%s\n", out);

    len = BIO_read(b, out, len);
    printf("BIO_read:%s\n", out);

    OPENSSL_free(out);
    BIO_free(b);
}


void test_file_bio()
{
    BIO*  b = NULL;
    int   len = 0;
    int   outLen = 0;
    char* out = NULL;
    char* in = "test file bio";

    printf("===============================================\n");
    b = BIO_new_file("bio_file.txt", "w");
    printf("method name:%s\n", BIO_method_name(b));
    printf("method type:%04x\n",BIO_method_type(b));


    len = BIO_write(b, in, strlen(in));
    printf("BIO_write: %d:%s\n", len, in);

    in = "openssl";
    len = BIO_printf(b, "%s", in);
    printf("BIO_printf: %d:%s\n", len, in);

    BIO_free(b);

    b = BIO_new_file("bio_file.txt", "r");
    len = BIO_pending(b);
    printf("total len:%d\n", len);


    len=50;
    out=(char *)OPENSSL_zalloc(len);
    len = 50;
    while(len > 0)
    {
        len = BIO_read(b, out+outLen, len);
        printf("BIO_read:%d\n", len);
        outLen += len;
    }
    printf("data:%s\n", out);
    OPENSSL_free(out);
    BIO_free(b);
}

void test_fd_bio()
{
    int   len = 0;
    char* out = NULL;
    printf("===============================================\n");

    BIO* bOut = BIO_new_fd(1, BIO_CLOSE);  //stdout
    BIO* bIn = BIO_new_fd(0, BIO_CLOSE);   // stdin
    printf("method name:%s\n", BIO_method_name(bIn));
    printf("method type:%04x\n",BIO_method_type(bIn));
    len=50;
    out=(char *)OPENSSL_zalloc(len);
    len = 50;
    while(len > 0)
    {
        len = BIO_read(bIn, out, len);
        printf("BIO_read:%d\n", len);
        len = BIO_write(bOut, out, len);
        printf("BIO_write:%d\n", len);
    }
    OPENSSL_free(out);
    BIO_free(bIn);
    BIO_free(bOut);
}

void test_md_bio()
{
    BIO *bmd = NULL,*b=NULL;
    const EVP_MD *md = EVP_md5();
    int len;
    char tmp[1024];
    memset(tmp, 0, 1024);

    printf("===============================================\n");
    bmd = BIO_new(BIO_f_md());
    printf("method name:%s\n", BIO_method_name(bmd));
    printf("method type:%04x\n",BIO_method_type(bmd));
    BIO_set_md(bmd,md);

    b = BIO_new(BIO_s_null());
    b = BIO_push(bmd,b);

    len = BIO_write(b,"openssl",8);
    len = BIO_gets(b,tmp,1024);
    for(int i = 0; i < strlen(tmp); i++)
    {
        printf("%08x ", tmp[i]);
    }
    printf("\n");

    BIO_free(b);
}


void test_ciper_bio()
{
    BIO *bc=NULL,*b=NULL;
    const EVP_CIPHER *c=EVP_des_ecb();
    int len,i, encLen;
    char tmp[1024];
    unsigned char key[8],iv[8];
    printf("===============================================\n");
    // 加密
    for(i=0;i<8;i++)
    {
        memset(&key[i],i+1,1);
        memset(&iv[i],i+1,1);
    }

    bc=BIO_new(BIO_f_cipher());
    printf("method name:%s\n", BIO_method_name(bc));
    printf("method type:%04x\n",BIO_method_type(bc));
    BIO_set_cipher(bc,c,key,iv,1);

    b= BIO_new(BIO_s_null());
    b=BIO_push(bc,b);
    len=BIO_write(b,"openssl",7);
    encLen=BIO_read(b,tmp,1024);
    printf("enc:\n");
    for(int i = 0; i < encLen; i++)
    {
        printf("%02x ", tmp[i]);
    }
    printf("\n");
    BIO_free(b);

    /* 解密 */
    BIO *bdec=NULL,*bd=NULL;
    const EVP_CIPHER *cd=EVP_des_ecb();
    bdec=BIO_new(BIO_f_cipher());
    BIO_set_cipher(bdec,cd,key,iv,0);
    bd= BIO_new(BIO_s_null());
    bd=BIO_push(bdec,bd);
    len=BIO_write(bdec,tmp,encLen);
    memset(tmp, 0, 1024);
    len=BIO_read(bdec,tmp, 1024);
    printf("denc:%s\n", tmp);
    BIO_free(bdec);
}


void test_ssl_bio()
{
    BIO *sbio, *out;
    int len;
    char tmpbuf[1024];
    SSL_CTX *ctx;
    SSL *ssl;
    printf("===============================================\n");
    SSLeay_add_ssl_algorithms();
    OpenSSL_add_all_algorithms();
    ctx = SSL_CTX_new(SSLv23_client_method());
    sbio = BIO_new_ssl_connect(ctx);
    BIO_get_ssl(sbio, &ssl);
    if(!ssl)
    {
        fprintf(stderr, "Can not locate SSL pointer\n");
        return;
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    BIO_set_conn_hostname(sbio, "github.com:https");
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_printf(out,"connecting... ...\n");
    if(BIO_do_connect(sbio) <= 0)
    {
        fprintf(stderr, "Error connecting to server\n");
        return;
    }
    if(BIO_do_handshake(sbio) <= 0)
    {
        fprintf(stderr, "Error establishing SSL connection\n");
        return;
    }
    BIO_puts(sbio, "GET / HTTP/1.0\n\n");
    for(;;)
    {
        len = BIO_read(sbio, tmpbuf, 1024);
        if(len <= 0) break;
        BIO_write(out, tmpbuf, len);
    }
    BIO_free_all(sbio);
    BIO_free(out);
}


void test_bio_indent()
{
    int ret,len,indent;
    BIO *bp;
    char *pp,buf[5000];
    FILE *fp;
    printf("===============================================\n");

    bp=BIO_new(BIO_s_file());
    BIO_set_fp(bp,stdout,BIO_NOCLOSE);
    printf("method name:%s\n", BIO_method_name(bp));
    printf("method type:%04x\n",BIO_method_type(bp));

    fp=fopen("der.cer","rb");
    len=fread(buf,1,5000,fp);
    fclose(fp);

    pp=buf;
    indent=10;
    ret=BIO_dump_indent(bp,pp,len,indent);
    BIO_free(bp);

}

int main(int argc, char const *argv[])
{
    test_mem_bio();
    test_file_bio();
    //test_fd_bio();
    test_md_bio();
    test_ciper_bio();
    //test_ssl_bio();
    //test_bio_indent();

    return 0;
}
