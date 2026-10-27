/*
 * stress_fork.c — Phase 2 stress test: PID limit / fork-bomb-lite
 *
 * Attempts to spawn child processes in a loop, stopping after a
 * configurable number of attempts so it cannot actually take down
 * the host even if cgroup limits are misconfigured.
 *
 * When run inside the sandbox with a pids.max limit, fork() calls
 * beyond the limit will fail with EAGAIN.
 *
 * Usage: ./stress_fork [max_attempts]
 *        Default: 100 attempts (safe ceiling)
 *
 * Verify: under a --profile strict sandbox (pids.max = 10), spawning
 *         more than 10 processes causes fork() to return EAGAIN.
 *         Only a handful of children should succeed before refusals start.
 *
 * Build:  gcc -O0 -o stress_fork stress_fork.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <string.h>

int main(int argc, char *argv[])
{
    int max_attempts = 100;
    if (argc > 1) max_attempts = atoi(argv[1]);

    printf("[stress_fork] PID = %d\n", getpid());
    printf("[stress_fork] Attempting %d fork()s...\n", max_attempts);
    fflush(stdout);

    int succeeded = 0;
    int failed    = 0;

    for (int i = 0; i < max_attempts; i++) {
        pid_t child = fork();

        if (child == 0) {
            /* Child: sleep long enough for external monitors to sample */
            usleep(2000000);  /* 2.0s */
            exit(0);

        } else if (child > 0) {
            succeeded++;
            printf("[stress_fork] fork #%d succeeded — child PID %d\n", i + 1, child);
            fflush(stdout);
            /* Small stagger so children are created progressively */
            usleep(10000);  /* 10ms */

        } else {
            /* fork() failed */
            if (errno == EAGAIN) {
                failed++;
                printf("[stress_fork] fork #%d BLOCKED by pids.max (EAGAIN)\n", i + 1);
            } else {
                printf("[stress_fork] fork #%d failed: %s\n", i + 1, strerror(errno));
            }
            fflush(stdout);
        }
    }

    /* Reap all children */
    int status;
    while (wait(&status) > 0) { /* keep going */ }

    printf("\n[stress_fork] Summary: %d succeeded, %d blocked/failed\n",
           succeeded, failed);
    return 0;
}
