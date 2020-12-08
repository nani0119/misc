#include <stdio.h>
#include <string.h>

#include <string>

#include <openssl/bio.h>
#include <openssl/txt_db.h>

// name  phone  email null

int id_filter(char** in)
{
    //printf("%s\n", __func__);
    if(in[0][0]-'0' < 10)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}


unsigned long id_hash(const char** in)
{
    //printf("%s\n", __func__);
    const char *n;

    n = in[0];
    while (*n == '0')
        n++;
    return OPENSSL_LH_strhash(n);
}

int id_cmp(const char** in1, const char** in2)
{
    //printf("%s\n", __func__);
    const char *aa, *bb;

    for (aa = in1[0]; *aa == '0'; aa++) ;
    for (bb = in2[0]; *bb == '0'; bb++) ;
    return strcmp(aa, bb);
}


void txt_db_gen()
{
    TXT_DB* db;
    int ret;
    char** row;
    BIO* out = BIO_new_file("txtdb.dat", "w");
    BIO* in = BIO_new_file("txtdb.dat", "r");

    if(!in)
    {
        printf("can not find txt db file\n");
        return;
    }

    db = TXT_DB_read(in, 5);

    for (int i = 1; i < 6; i++)
    {
        // id name  phone  email null
        row = (char **)OPENSSL_zalloc(sizeof(char *) * (4 + 1));

        row[0] = (char *)OPENSSL_malloc(10);
        row[0][0] = i + '0';

        row[1] = (char *)OPENSSL_malloc(10);
        strncpy(row[1], "bbbbbbbbb", i);

        row[2] = (char *)OPENSSL_malloc(10);
        strncpy(row[2], "12345679", i);

        row[3] = (char *)OPENSSL_malloc(10);
        strncpy(row[3], "bob@b.com", i);

        row[4] = NULL;

        ret = TXT_DB_insert(db, row);

        if (ret != 1)
        {
            printf("insert data fail");
        }
    }

    TXT_DB_write(out, db);
    TXT_DB_free(db);  // free malloc
    BIO_free(in);
    BIO_free(out);
}



void txt_db_list()
{
    int ret;
    BIO* in = BIO_new_file("txtdb.dat","r");
    if(!in)
    {
        printf("load txt db fail\n");
        return;
    }

    TXT_DB *db = TXT_DB_read(in, 5);
    if(!db)
    {
        printf("read txt db fail\n");
        return;
    }

    // 0 列建立索引
    ret = TXT_DB_create_index(db, 0, id_filter, id_hash, id_cmp);
    if(ret != 1)
    {
        printf("create txt db index fail\n");
        goto end;
    }

    for(int i = 1; i < 6; i++)
    {
        char** result_row;
        char** row=(char **)OPENSSL_zalloc(sizeof(char *) * (4 + 1));

        row[0] = (char *)OPENSSL_malloc(10);
        row[0][0] = i + '0';

        row[1] = NULL;
        row[2] = NULL;
        row[3] = NULL;
        row[4] = NULL;


        result_row = TXT_DB_get_by_index(db, 0, row);
        if(result_row != NULL)
        {
            // id name  phone  email null
            for(int j = 0; result_row[j]; j++)
            {
                printf("%s\t", result_row[j]);
            }
            printf("\n");
        }
        else
        {
            printf("not find item in db\n");
        }
        
    }

end:
    TXT_DB_free(db);
    BIO_free(in);


}

int main(int argc, char const *argv[])
{
    txt_db_gen();
    txt_db_list();
    return 0;
}

