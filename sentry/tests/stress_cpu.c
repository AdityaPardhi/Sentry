/*
 * stress_cpu.c — Phase 2 stress test: CPU hog
 *
 * Runs a tight infinite loop to saturate one CPU core.
 * When run inside the sandbox with a CPU cap, the process should be
 * throttled to the configured percentage (e.g., 30%).
 *
 * Usage: ./stress_cpu [seconds]
 *        Default: runs for 30 seconds then exits.
 *
 * Verify: run `top` or `htop` from outside the sandbox and observe the
 *         CPU% column for this process is capped near the profile limit.
 *
 * Build:  gcc -O2 -o stress_cpu stress_cpu.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[])
{
    int seconds = 30;
    if (argc > 1) seconds = atoi(argv[1]);

    printf("[stress_cpu] Burning CPU for %d seconds...\n", seconds);
    fflush(stdout);

    time_t start = time(NULL);

    volatile unsigned long counter = 0;
    while (time(NULL) - start < seconds) {
        counter++;   /* tight loop — no sleep, no syscalls */
    }

    printf("[stress_cpu] Done. counter = %lu\n", counter);
    return 0;
}
