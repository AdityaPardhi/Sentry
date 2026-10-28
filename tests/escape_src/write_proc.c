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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

int main(void)
{
    const char *path = "/proc/sysrq-trigger";
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "[escape] open(%s): %s — blocked\n", path, strerror(errno));
        return 1;
    }

    ssize_t n = write(fd, "b", 1);  /* 'b' = reboot */
    if (n < 0) {
        fprintf(stderr, "[escape] write(%s): %s — blocked\n", path, strerror(errno));
        close(fd);
        return 1;
    }

    struct stat st;
    if (fstat(fd, &st) == 0 && S_ISCHR(st.st_mode) && st.st_rdev == makedev(1, 3)) {
        fprintf(stderr, "[escape] neutralised: masked to /dev/null\n");
        close(fd);
        return 1;
    }

    close(fd);
    fprintf(stderr, "[escape] WRITE SUCCEEDED — escape!\n");
    return 0;  /* escape succeeded — test will FAIL */
}
