/*
 * stress_mem.c — Phase 2 stress test: memory hog
 *
 * Allocates and touches memory in 10 MB chunks until either:
 *   a) the cgroup memory limit kills it (OOM kill), or
 *   b) it reaches the configured ceiling and exits normally.
 *
 * Usage: ./stress_mem [max_mb]
 *        Default: allocates up to 600 MB (crosses the 512MB "strict" cap).
 *
 * Verify: check `dmesg | grep -i oom` for an OOM kill message, and
 *         look at /sys/fs/cgroup/sentry_sandbox/memory.events for the
 *         'oom_kill' counter after the test.
 *
 * Build:  gcc -O0 -o stress_mem stress_mem.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHUNK_MB  10
#define CHUNK     (CHUNK_MB * 1024 * 1024)

int main(int argc, char *argv[])
{
    int max_mb = 600;
    if (argc > 1) max_mb = atoi(argv[1]);

    printf("[stress_mem] Will allocate up to %d MB in %d MB chunks...\n",
           max_mb, CHUNK_MB);
    printf("[stress_mem] PID = %d\n", getpid());
    fflush(stdout);

    long allocated_mb = 0;

    while (allocated_mb < max_mb) {
        char *buf = malloc(CHUNK);
        if (!buf) {
            printf("[stress_mem] malloc failed at %ld MB — out of memory\n",
                   allocated_mb);
            break;
        }

        /*
         * Touch every page so the kernel actually maps them.
         * malloc() is lazy — pages are only allocated on first write.
         * memset forces the OS to commit real physical memory.
         */
        memset(buf, 0xAB, CHUNK);

        allocated_mb += CHUNK_MB;
        printf("[stress_mem] Allocated %ld MB\n", allocated_mb);
        fflush(stdout);

        /* 200ms pause so we can observe the climb in real time */
        usleep(200000);
    }

    printf("[stress_mem] Finished — holding %ld MB. Sleeping 5s...\n",
           allocated_mb);
    fflush(stdout);
    sleep(5);

    return 0;
}
