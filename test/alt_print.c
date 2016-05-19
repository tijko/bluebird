#include <stdio.h>
#include <unistd.h>

char *process = "Process";

int main(int argc, char *argv[])
{
    pid_t pid = getpid();

    while ( 1 ) {

        printf("%s <%d> is running!\n", process, pid);
        sleep(2);
    }
        
    return 0;
}
