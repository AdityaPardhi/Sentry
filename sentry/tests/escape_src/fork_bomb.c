/*
 * fork_bomb.c — Forks until PID limit is hit.
 * Should be killed by the cgroup pids.max controller before it can
 * exhaust system PIDs.
 * Expected result: fork() returns EAGAIN when PID limit hit → exit non-zero.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#define MAX_FORKS 200

int main(void)
{
    /* Ignore SIGCHLD so we don't accumulate zombies */
    signal(SIGCHLD, SIG_IGN);

    int forked = 0;
    for (int i = 0; i < MAX_FORKS; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            fprintf(stderr, "[escape] fork() after %d children: %s — cgroup PID limit hit\n",
                    forked, strerror(errno));
            return 1;  /* blocked — test PASS */
        }
        if (pid == 0) {
            /* Child: just sleep and exit */
            sleep(5);
            _exit(0);
        }
        forked++;
    }

    fprintf(stderr, "[escape] FORK BOMB: successfully created %d children without limit\n", forked);
    return 0;  /* escape succeeded — test FAIL */
}
