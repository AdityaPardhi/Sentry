/*
 * read_host_file.c - Tries to reach HOST files via path traversal / old root.
 *
 * Inside the sandbox, /etc/passwd and ../../../etc/passwd resolve to the
 * sandbox root's OWN /etc/passwd (".." at the root stays at the root), so a
 * successful read of those is NOT an escape. A path counts as an escape only
 * if it opens a file that is different (st_dev/st_ino) from the sandbox's own
 * /etc/passwd, e.g. through a leftover /.old_root mount.
 * Expected result: nothing escapes -> exit 1 (blocked).
 * Exit 0 means an escape succeeded.
 */
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>

int main(void)
{
    struct stat own;
    memset(&own, 0, sizeof(own));
    int have_own = 0;
    int ofd = open("/etc/passwd", O_RDONLY);
    if (ofd >= 0) {
        if (fstat(ofd, &own) == 0)
            have_own = 1;
        close(ofd);
    }

    const char *paths[] = {
        "../../../etc/passwd",
        "/.old_root/etc/passwd",
        "/.old_root/etc/hostname",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        int fd = open(paths[i], O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "[escape] open(%s): %s\n", paths[i], strerror(errno));
            continue;
        }
        struct stat st;
        int ok = (fstat(fd, &st) == 0);
        close(fd);
        if (ok && have_own && st.st_dev == own.st_dev && st.st_ino == own.st_ino) {
            fprintf(stderr, "[escape] %s is the sandbox's own file - not an escape\n", paths[i]);
            continue;
        }
        fprintf(stderr, "[escape] READ HOST FILE SUCCESS via %s - escape!\n", paths[i]);
        return 0;
    }

    fprintf(stderr, "[escape] All path traversal attempts blocked.\n");
    return 1;
}
