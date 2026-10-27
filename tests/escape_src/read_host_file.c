/*
 * read_host_file.c — Tries to read /etc/passwd via path traversal.
 * Should be blocked by pivot_root (no access to old root) or
 * the read-only bind-mount.
 * Expected result: open() fails with ENOENT or EACCES → exit non-zero.
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void)
{
    const char *paths[] = {
        "../../../etc/passwd",
        "/etc/passwd",
        "/.old_root/etc/passwd",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        int fd = open(paths[i], O_RDONLY);
        if (fd >= 0) {
            char buf[256];
            ssize_t n = read(fd, buf, sizeof(buf) - 1);
            close(fd);
            if (n > 0) {
                buf[n] = '\0';
                fprintf(stderr, "[escape] READ HOST FILE SUCCESS via %s:\n%s\n", paths[i], buf);
                /* Signal escape succeeded — exit 0 so the test script marks FAIL */
                return 0;
            }
        } else {
            fprintf(stderr, "[escape] open(%s): %s\n", paths[i], strerror(errno));
        }
    }

    fprintf(stderr, "[escape] All path traversal attempts blocked.\n");
    return 1;
}
