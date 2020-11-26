#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/lhash.h>

typedef struct Student_st
{
    char name[20];
    int age;
    char otherInfo[200];
} Student;

int studentCompare(const void *a, const void *b)
{
    const char *namea = ((const Student*)a)->name;
    const char *nameb = ((const Student*)b)->name;
    return strcmp(namea, nameb);
}

void printValue(void *a)
{
    printf("name :%s\n", ((Student *)a)->name);
    printf("age :%d\n", ((Student *)a)->age);
    printf("otherInfo : %s\n", ((Student *)a)->otherInfo);
}

void printValueWithArg(void *a, void *b)
{
    int flag = 0;
    flag = *(int*)b;
    printf("flag:%d\n", flag);
    printf("name :%s\n", ((Student *)a)->name);
    printf("age :%d\n", ((Student *)a)->age);
    printf("otherInfo : %s\n", ((Student *)a)->otherInfo);
}

int main()
{
    int flag = 11;
    OPENSSL_LHASH *h;
    Student s1 = {"zcp", 28, "hu bei"},
            s2 = {"forxy", 28, "no info"},
            s3 = {"skp", 24, "student"},
            s4 = {"zhao_zcp", 28, "zcp's name"},
            *s5;
    void *data;
    h = OPENSSL_LH_new(NULL, studentCompare);
    if (h == NULL)
    {
        printf("err.\n");
        return -1;
    }
    data = &s1;
    OPENSSL_LH_insert(h, data);
    data = &s2;
    OPENSSL_LH_insert(h, data);
    data = &s3;
    OPENSSL_LH_insert(h, data);
    data = &s4;
    OPENSSL_LH_insert(h, data);
    /* 打印*/
    OPENSSL_LH_doall(h, printValue);
    printf("========================================\n");
    OPENSSL_LH_doall_arg(h, printValueWithArg, (void *)(&flag));
    data = OPENSSL_LH_retrieve(h, (const void *)"skp");
    if (data == NULL)
    {
        printf("can not look up skp!\n");
        OPENSSL_LH_free(h);
        return -1;
    }
    s5 = (Student*)data;
    printf("student name : %s\n", s5->name);
    printf("sutdent age : %d\n", s5->age);
    printf("student otherinfo : %s\n", s5->otherInfo);
    OPENSSL_LH_free(h);
    return 0;
}