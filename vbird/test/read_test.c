#include <stdio.h>
#include <unistd.h>


int main(int argc, char *argv[])
{

    char buf[4092];

    while ( 1 ) {
        FILE *fh = fopen("alt_print.c", "r");
        int b = fread(buf, 1, 1024, fh);
        if (b < 0)
            printf("err\n");
        else {
            printf("Read: %d\n", b);
            buf[b] = '\0';
            printf("%s\n", buf);
        }
            
        fclose(fh);
        sleep(1);
    }

    return 0;
}

