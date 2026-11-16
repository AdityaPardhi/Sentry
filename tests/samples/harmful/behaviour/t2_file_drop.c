/* t2_file_drop.c -- writes several files; should be SUSPICIOUS */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    char path[256];
    for (int i = 0; i < 30; i++) {
        snprintf(path, sizeof(path), "/tmp/sentry_drop_%03d.txt", i);
        FILE *f = fopen(path, "w");
        if (f) {
            fprintf(f, "dropped file %d\n", i);
            fclose(f);
        }
    }
    printf("t2_file_drop: wrote 30 files\n");
    return 0;
}

