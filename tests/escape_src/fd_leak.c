#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int main(void)
{
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) {
        fprintf(stderr, "[escape] opendir(/proc/self/fd) failed: %s — blocked\n", strerror(errno));
        return 1;
    }

    int dir_fd = dirfd(dir);
    struct dirent *de;
    int leaked = 0;

    while ((de = readdir(dir)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0)
            continue;

        int fd = atoi(de->d_name);
        if (fd >= 3 && fd != dir_fd) {
            fprintf(stderr, "[escape] Leaked fd %d found — escape!\n", fd);
            leaked = 1;
        }
    }
    closedir(dir);

    if (leaked) {
        return 0;
    }

    fprintf(stderr, "[escape] No leaked file descriptors found — blocked\n");
    return 1;
}
