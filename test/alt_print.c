#include <stdio.h>
#include <unistd.h>

char *process = "Process";

int main(int argc, char *argv[])
{
    setlinebuf(stdout);
    pid_t sid, pid = getpid();
    int count = 0;

    while ( 1 ) {

        printf("%s <%d> is running!\n", process, pid);
        sleep(1);
        count++;

        if (count == 10)
            sid = getsid(pid);
    }
        
    printf("Session id: %d\n", sid);

    return 0;
}
