/*
 * write_proc.c — Tries to write to /proc/sysrq-trigger.
 * Should be blocked because /proc/sysrq-trigger is masked with /dev/null.
 * Expected result: write fails → exit non-zero.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void)
{
    const char *path = "/proc/sysrq-trigger";
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "[escape] open(%s): %s — blocked\n", path, strerror(errno));
        return 1;
    }

    ssize_t n = write(fd, "b", 1);  /* 'b' = reboot */
    close(fd);
    if (n >= 0) {
        fprintf(stderr, "[escape] write(%s): %s — blocked\n", path, strerror(errno));
        return 1;
    }

    fprintf(stderr, "[escape] WRITE TO %s SUCCEEDED — escape!\n", path);
    return 0;  /* escape succeeded — test will FAIL */
}
