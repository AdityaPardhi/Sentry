/* t5_spawner.c -- forks many child processes; should be SUSPICIOUS */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define NFORKS 20

int main(void) {
    pid_t pids[NFORKS];
    int spawned = 0;
    for (int i = 0; i < NFORKS; i++) {
        pid_t p = fork();
        if (p < 0) {
            printf("[t5] fork %d failed\n", i);
            break;
        }
        if (p == 0) {
            /* child: sleep briefly then exit */
            usleep(200000);
            exit(0);
        }
        pids[spawned++] = p;
    }
    printf("[t5] spawned %d children\n", spawned);
    for (int i = 0; i < spawned; i++)
        waitpid(pids[i], NULL, 0);
    return 0;
}

