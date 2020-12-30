#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>

#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/crypto.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>

typedef struct seq_x509
{
    X509_ALGOR alg;

} SEQ_X509;

//　指明如何生成SEQ_X509以及如何ASN1编码，　X509_ALGOR类似，但是openssl库已经提前定义好了
ASN1_SEQUENCE(SEQ_X509) = {
        ASN1_EMBED(SEQ_X509, alg, X509_ALGOR)
} 
ASN1_SEQUENCE_END(SEQ_X509)

DECLARE_ASN1_FUNCTIONS(SEQ_X509)
IMPLEMENT_ASN1_FUNCTIONS(SEQ_X509)

int store_SEQ_X509()
{
    printf("==============================%s==============================\n",__func__);
    BIO *fbio = BIO_new_file("x509.der", "w");
    char* data = "hello world";

    SEQ_X509* x509 = SEQ_X509_new();


    x509->alg.algorithm=OBJ_nid2obj(NID_sha256);
    x509->alg.parameter=ASN1_TYPE_new();
    ASN1_TYPE_set_octetstring(x509->alg.parameter, data, strlen(data));

    int len = i2d_SEQ_X509(x509, NULL);
    unsigned char* alg_buf = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*len);
    unsigned char* p = alg_buf;
    len = i2d_SEQ_X509(x509, &p);
    
    BIO_write(fbio, alg_buf, len);
    BIO_flush(fbio);

    OPENSSL_free(alg_buf);
    //X509_ALGOR_free(x509->alg);
    SEQ_X509_free(x509);
    BIO_free(fbio);
    return len;
}

void load_SEQ_X509(int len)
{
    printf("==============================%s==============================\n",__func__);
    BIO *fbio = BIO_new_file("x509.der", "r");
    char data[]={"hello world"};
    unsigned char* alg_buf = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*len);
    unsigned char* p = alg_buf;
    BIO_read(fbio, alg_buf, len);

    SEQ_X509* x509 = SEQ_X509_new();
    //x509->alg = X509_ALGOR_new();
    d2i_SEQ_X509(&x509, &p, len);

    if(OBJ_obj2nid(x509->alg.algorithm) == NID_sha256)
    {
        printf("algorithm:NID_sha256\n");
        memset(data, 0, sizeof(data));
        ASN1_TYPE_get_octetstring(x509->alg.parameter, data, sizeof(data));
        printf("parameter:%s\n", data);
    }
    OPENSSL_free(alg_buf);
    //X509_ALGOR_free(x509->alg);
    SEQ_X509_free(x509);
    BIO_free(fbio);
}

void x509_alg()
{
    printf("==============================%s==============================\n",__func__);
    char data[]={"hello world"};

    BIO *fbio = BIO_new_file("algor.der", "w");

    X509_ALGOR *alg = X509_ALGOR_new();
    ASN1_OBJECT* alg_obj= OBJ_nid2obj(NID_sha256);
    //X509_ALGOR_set0(alg, alg_obj, V_ASN1_OCTET_STRING, data);
    alg->algorithm=OBJ_nid2obj(NID_sha256);
    alg->parameter=ASN1_TYPE_new();
    ASN1_TYPE_set_octetstring(alg->parameter, data, strlen(data));

    int len = i2d_X509_ALGOR(alg, NULL);
    unsigned char* alg_buf = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*len);
    unsigned char* p = alg_buf;
    len = i2d_X509_ALGOR(alg, &p);

    BIO_write(fbio, alg_buf, len);
    BIO_flush(fbio);


    OPENSSL_free(alg_buf);
    X509_ALGOR_free(alg);
    BIO_free(fbio);
    //========================================================================
    fbio = BIO_new_file("algor.der", "r");
    alg_buf = (unsigned char*)OPENSSL_malloc(sizeof(unsigned char)*len);
    p = alg_buf;
    X509_ALGOR *alg_dup = X509_ALGOR_new();
    BIO_read(fbio, alg_buf, len);
    d2i_X509_ALGOR(&alg_dup,&p,len);

    if(OBJ_obj2nid(alg_dup->algorithm) == NID_sha256)
    {
        printf("algorithm:NID_sha256\n");
        memset(data, 0, sizeof(data));
        ASN1_TYPE_get_octetstring(alg_dup->parameter, data, sizeof(data));
        printf("parameter:%s\n", data);
    }
    X509_ALGOR_free(alg_dup);
    BIO_free(fbio);
    OPENSSL_free(alg_buf);
}


int main(int argc, char const *argv[])
{
    //x509_alg();
    int len = store_SEQ_X509();
    printf("len:%d\n", len);
    load_SEQ_X509(len);
    x509_alg();
    return 0;
}
