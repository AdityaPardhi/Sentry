/*
 * mknod_dev.c — Tries to create a block device node.
 * Should be blocked by seccomp (mknod/mknodat removed from allow-list).
 * Expected result: SIGSYS or EPERM → exit non-zero.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sysmacros.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void)
{
    /* Try to create /dev/sda (block device, major 8 minor 0) */
    dev_t dev = makedev(8, 0);
    int rc = mknod("/tmp/sda", S_IFBLK | 0600, dev);
    if (rc != 0) {
        fprintf(stderr, "[escape] mknod(/tmp/sda): %s — blocked\n", strerror(errno));
        return 1;
    }

    fprintf(stderr, "[escape] MKNOD SUCCEEDED — escape!\n");
    return 0;  /* escape succeeded — test will FAIL */
}
