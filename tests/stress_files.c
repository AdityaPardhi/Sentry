/*
 * stress_files.c — Phase 5 stress test: Rapid file creation and modification
 *
 * Creates, writes to, and deletes a configurable number of files in a tight loop.
 * Triggers inotify IN_CREATE, IN_MODIFY, and IN_DELETE events to test the
 * FileMonitor rate calculation (files/minute).
 *
 * Usage: ./stress_files [count] [dir]
 *        Default: 200 files in /tmp
 *
 * Build: gcc -O2 -o stress_files stress_files.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

int main(int argc, char *argv[])
{
    int count = 200;
    const char *target_dir = "/tmp";

    if (argc > 1) count = atoi(argv[1]);
    if (argc > 2) target_dir = argv[2];

    printf("[stress_files] Rapidly creating %d files in '%s'...\n", count, target_dir);
    fflush(stdout);

    /* Ensure target directory exists */
    mkdir(target_dir, 0755);

    char filepath[512];
    const char *payload = "SENTRY sandbox file activity test payload.\n";
    size_t payload_len = strlen(payload);

    struct timespec ts_start, ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    int created = 0;
    for (int i = 0; i < count; i++) {
        snprintf(filepath, sizeof(filepath), "%s/sentry_burst_%d.tmp", target_dir, i);

        int fd = open(filepath, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            ssize_t w = write(fd, payload, payload_len);
            (void)w;
            close(fd);
            created++;
        }

        /* 8ms delay between files so monitor samples progressive creation */
        usleep(8000);
    }

    printf("[stress_files] Created %d files. Now deleting...\n", created);
    fflush(stdout);

    int deleted = 0;
    for (int i = 0; i < count; i++) {
        snprintf(filepath, sizeof(filepath), "%s/sentry_burst_%d.tmp", target_dir, i);
        if (unlink(filepath) == 0) {
            deleted++;
        }
        usleep(4000);
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    double elapsed = (ts_end.tv_sec - ts_start.tv_sec) + (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;
    printf("[stress_files] Finished: %d created, %d deleted in %.2f seconds.\n",
           created, deleted, elapsed);

    return 0;
}
