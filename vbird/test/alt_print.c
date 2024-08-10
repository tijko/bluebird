#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


char *process = "Process";

static inline void set_path(void)
{
    char *home = getenv("HOME");
    char path[4096];
    snprintf(path, 4095, "%s:%s", home, getenv("PATH"));
    setenv("PATH", path, 1);
}

int main(int argc, char *argv[])
{
    setlinebuf(stdout);
    pid_t sid, pid = getpid();
    int count = 0;
    printf("Starting...\n");

    set_path();

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
