#include <stdlib.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>

/*
asn1 = SEQUENCE:seq_section

[seq_section]
field1 = BOOLEAN:TRUE
field2 = INTEGER:0x01
field3 = SEQUENCE:seq_child
 
[seq_child]
field1 = INTEGER:0x02
field2 = INTEGER:0x03
*/

 typedef struct SeqChild_st
 {
    ASN1_INTEGER*   value1;
    ASN1_INTEGER*   value2;
 } SEQ_CHILD;
 DECLARE_ASN1_FUNCTIONS(SEQ_CHILD);

ASN1_SEQUENCE(SEQ_CHILD) = 
{
    ASN1_SIMPLE(SEQ_CHILD, value1, ASN1_INTEGER),
    ASN1_SIMPLE(SEQ_CHILD, value2, ASN1_INTEGER)
}
ASN1_SEQUENCE_END(SEQ_CHILD)
IMPLEMENT_ASN1_FUNCTIONS(SEQ_CHILD)

typedef struct SeqSection_st
{
   ASN1_BOOLEAN            flag;
   ASN1_INTEGER*           value;
   SEQ_CHILD*              child_seq;
} SEQ_SECTION;
DECLARE_ASN1_FUNCTIONS(SEQ_SECTION);
ASN1_SEQUENCE(SEQ_SECTION) =
{
    ASN1_SIMPLE(SEQ_SECTION, flag, ASN1_BOOLEAN),
    ASN1_SIMPLE(SEQ_SECTION, value, ASN1_INTEGER),
    ASN1_SIMPLE(SEQ_SECTION, child_seq, SEQ_CHILD)
}
ASN1_SEQUENCE_END(SEQ_SECTION)
IMPLEMENT_ASN1_FUNCTIONS(SEQ_SECTION)


void asn1_dec_codec()
{
    unsigned char derEcode[1024] = {0};
    int ret;
    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO* outFile = BIO_new_file("section.cer", "w");
    BIO* inFile = BIO_new_file("section.cer", "r");
    BIO* base64Bio = BIO_new(BIO_f_base64());
    BIO_push(base64Bio, out);
    printf("====================================================================\n");
    SEQ_SECTION* section = SEQ_SECTION_new();

    // construct
    section->flag = 0x01;
    section->value = ASN1_INTEGER_new();
    ASN1_INTEGER_set(section->value, 0x01);
    section->child_seq = SEQ_CHILD_new();

    section->child_seq->value1 = ASN1_INTEGER_new();
    section->child_seq->value2 = ASN1_INTEGER_new();

    ASN1_INTEGER_set(section->child_seq->value1, 0x02);
    ASN1_INTEGER_set(section->child_seq->value2, 0x03);
    //=================================================================

    // encode
    ret = i2d_SEQ_SECTION(section, (unsigned char**)&derEcode);
    printf("ret:%d\n",ret);
    
    printf("i2d: ");
    for(int i = 0; i < ret; i++)
    {
        printf("%02x ", derEcode[i]);
    }
    printf("\n");

    printf("-------------------------------------------------------------------------\n");
    printf("i2d base64: ");
    ASN1_i2d_bio(i2d_SEQ_SECTION, base64Bio, derEcode);
    BIO_flush(base64Bio);
    //==================================================================

    // decode
    SEQ_SECTION* decSection = SEQ_SECTION_new();
    d2i_SEQ_SECTION(&decSection, (unsigned char**)&derEcode, ret);

    printf("seq section:\n");
    printf("\tflag:%d\n", decSection->flag);
    printf("\tvalude:%d\n", ASN1_INTEGER_get(decSection->value));
    printf("\tseq child:\n");
    printf("\t\tvalude1:%d\n", ASN1_INTEGER_get(decSection->child_seq->value1));
    printf("\t\tvalude1:%d\n", ASN1_INTEGER_get(decSection->child_seq->value2));
    
    printf("--------------------111-----------------------------------------------------\n");
    // =====================save to file==========================
    ASN1_i2d_bio(i2d_SEQ_SECTION, outFile, (unsigned char*)section);
    BIO_flush(outFile);
    printf("--------------------222-----------------------------------------------------\n");
    //===================================================================
    SEQ_SECTION** decBioOutSection;
    decBioOutSection=(SEQ_SECTION **)OPENSSL_malloc(sizeof(SEQ_SECTION **));
    SEQ_SECTION* decBioSection = (SEQ_SECTION*)ASN1_d2i_bio(NULL, d2i_SEQ_SECTION, inFile, decBioOutSection);
    printf("seq section:\n");
    printf("\tflag:%d\n", decBioSection->flag);
    printf("\tvalude:%d\n", ASN1_INTEGER_get(decBioSection->value));
    printf("\tseq child:\n");
    printf("\t\tvalude1:%d\n", ASN1_INTEGER_get(decBioSection->child_seq->value1));
    printf("\t\tvalude1:%d\n", ASN1_INTEGER_get(decBioSection->child_seq->value2));




    SEQ_SECTION_free(decBioSection);
    SEQ_SECTION_free(decSection);
    SEQ_SECTION_free(section);
    BIO_free_all(base64Bio);
    BIO_free(outFile);
    BIO_free(inFile);
    OPENSSL_free(decBioOutSection);
}


int main(int argc, char const *argv[])
{
    asn1_dec_codec();
    return 0;
}
