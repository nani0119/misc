#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <thread>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

// sink/source

void ss_file_bio()
{
    printf("====================================================\n");
    BIO* bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
    BIO_printf(bio_out, "Hello world\n");
    BIO_free(bio_out);
    //==========================

    bio_out = BIO_new(BIO_s_file());
    BIO_set_fp(bio_out, stdout, BIO_NOCLOSE);
    BIO_printf(bio_out, "Hello world\n");
    BIO_free(bio_out);

    //===========================
    char buf[16] = {0};
    bio_out = BIO_new_file("ss_file.txt", "w");
    BIO_write(bio_out, "Hello ", 6);
    BIO_printf(bio_out, "%s", "world");
    BIO_free(bio_out);

    bio_out = BIO_new_file("ss_file.txt", "r");
    BIO_read(bio_out, buf, 16);
    printf("%s\n", buf);
    BIO_free(bio_out);

    //============================
    memset(buf, 0, 16);
    bio_out = BIO_new(BIO_s_file());
    //BIO_rw_filename
    BIO_write_filename(bio_out, (void*)"ss_fd.txt");
    BIO_printf(bio_out, "%s", "Hello ");
    BIO_free(bio_out);

    bio_out = BIO_new(BIO_s_file());
    BIO_append_filename(bio_out, (void*)"ss_fd.txt");
    BIO_write(bio_out, "world", 5);
    BIO_free(bio_out);

    bio_out = BIO_new(BIO_s_file());
    BIO_read_filename(bio_out, "ss_fd.txt");
    BIO_read(bio_out, buf, 16);
    printf("%s\n", buf);
    BIO_free(bio_out);

    //============================
    bio_out = BIO_new(BIO_s_fd());
    BIO_set_fd(bio_out, fileno(stdout), BIO_NOCLOSE);
    BIO_puts(bio_out, "Hello world\n");
    BIO_free(bio_out);
}

void ss_null_bio()
{
    char buf[16] = {'a'};
    BIO* bio = BIO_new(BIO_s_null());
    printf("====================================================\n");
    BIO_write(bio, "Hello world\n", 11);
    BIO_read(bio, buf, 16);
    printf("%s\n", buf);
    BIO_free(bio);
}

void ss_mem_bio()
{
    printf("====================================================\n");
    char buf[16] = {0};

    BIO* bio = BIO_new(BIO_s_mem());
    // 不释放BUF_MEM结构
    BIO_set_close(bio, BIO_NOCLOSE);

    BIO_puts(bio, "Hello world");
    BIO_read(bio, buf, 11);
    printf("%s", buf);

    char* pbuf;
    long len = BIO_get_mem_data(bio, &pbuf);
    printf("%s\n", pbuf);
    
    // 取出BUF_MEM结构
    BUF_MEM* bmPtr;
    BIO_get_mem_ptr(bio, &bmPtr);
    printf("%s\n", bmPtr->data);
    BUF_MEM_free(bmPtr);
    BIO_free(bio);

    //===========================================================
    bio = BIO_new(BIO_s_mem());
    BIO_set_close(bio, BIO_NOCLOSE);
    BUF_MEM* bmPtrNew = (BUF_MEM*)OPENSSL_zalloc(sizeof(BUF_MEM));
    bmPtrNew->length = 2;
    bmPtrNew->data = "HW";
    BIO_set_mem_buf(bio, bmPtrNew, BIO_NOCLOSE);
    memset(buf, 0 , 16);
    BIO_read(bio, buf, 11);
    printf("%s\n", buf);
    OPENSSL_free(bmPtrNew);
    BIO_free(bio);

    //==============================================================
    char data[] = "Hello World";
    bio = BIO_new_mem_buf(data, -1);
    memset(buf, 0 , 16);
    BIO_read(bio, buf, 11);
    printf("%s\n", buf);
    BIO_free(bio);

    //==========================================
    memset(buf, 0 , 16);
    bio = BIO_new(BIO_s_mem());
    BIO_set_mem_eof_return(bio,5);
    len = BIO_read(bio, buf, 11);
    printf("%d\n", len);
    BIO_free(bio);
}

void ss_bio_bio()
{
    printf("====================================================\n");
    char buf[16] = {0};
    BIO* bio1 = BIO_new(BIO_s_bio());
    BIO* bio2 = BIO_new(BIO_s_bio());
    //int BIO_new_bio_pair(BIO **bio1, size_t writebuf1, BIO **bio2, size_t writebuf2);
    BIO_make_bio_pair(bio1,bio2);

    BIO_write(bio1,"hello world", 11);
    BIO_flush(bio1);
    BIO_read(bio2, buf, 16);
    printf("%s\n", buf);

    BIO_write(bio2,"HELLO WORLD", 11);
    BIO_flush(bio2);
    BIO_read(bio1, buf, 16);
    printf("%s\n", buf);

    BIO_free(bio1);
    BIO_free(bio2);
}

void ss_connect_bio()
{
    printf("====================================================\n");
    char buf[16];
    int len;
    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
#if 0
    BIO* clientBio = BIO_new(BIO_s_connect());
    BIO_set_conn_hostname(clientBio, "local");
    BIO_set_conn_address(clientBio, "127.0.0.1");
    BIO_set_conn_port(clientBio,"9999");
#else
    BIO* clientBio =  BIO_new_connect("127.0.0.1:9999");
    BIO_set_nbio(clientBio, 0);
#endif
    if(BIO_do_connect(clientBio) <= 0)
    {
        printf("connect fail\n");
        return;
    }
    while(1)
    {
        len = BIO_read(clientBio, buf, 16);
        if(buf[0] == 'q')
            break;
        BIO_write(out, buf, len);
        BIO_flush(out);
    }

    BIO_free(out);
    BIO_free(clientBio);

}

void ss_accept_bio()
{
    printf("*****************************************************\n");
    int len;
    char buf[16] = {0};
    BIO* in = BIO_new_fp(stdin, BIO_NOCLOSE);
#if 1
    BIO* serverBio = BIO_new_accept("9999");
#else
    BIO* serverBio = BIO_new(BIO_s_accept());
    BIO_set_accept_port(serverBio, "9999");
#endif

     /* 首先调用BIO_accept启动接受BIO */
     if(BIO_do_accept(serverBio) <= 0) 
     {
         printf("Error setting up accept\n");
         return;
     }
     /* 等待连接建立*/
     if(BIO_do_accept(serverBio) <= 0) 
     {
         printf("Error accepting connection\n");
         return;
     }


    BIO* cbio = BIO_pop(serverBio);
    BIO_puts(cbio, "Connected\n");

    printf("type q for exit\n");
    while(1)
    {
        len = BIO_read(in, buf, 1);
        BIO_write(cbio, buf, len);
        if(buf[0] == 'q')
        {
            break;
        }
    }

    BIO_free(cbio);
    BIO_free(in);
    BIO_free(serverBio);
}
// filter type

void f_null_bio()
{
    printf("====================================================\n");
    // 简单传递到BIO链中的下一个BIO
    BIO* fNull = BIO_new(BIO_f_null());
    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_push(fNull, out);
    BIO_puts(fNull, "hello world\n");

    BIO_free_all(fNull);
}

int main(int argc, char const *argv[])
{
    // source/sink type
    ss_file_bio();
    ss_null_bio();
    ss_mem_bio();
    ss_bio_bio();
#if 0
    std::thread s {ss_accept_bio};
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    std::thread c {ss_connect_bio};
    c.join();
    s.join();
#endif
    f_null_bio();

    return 0;
}
