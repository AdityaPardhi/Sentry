/* t3_secret_reader.c -- tries to read /etc/shadow; should be DANGEROUS/MALICIOUS */
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* static scanner picks up the /etc/shadow reference */
static const char *targets[] = {
    "/etc/shadow",
    "/etc/passwd",
    "/root/.ssh/authorized_keys",
    NULL,
};

int main(void) {
    for (int i = 0; targets[i]; i++) {
        FILE *f = fopen(targets[i], "r");
        if (f) {
            char buf[128];
            while (fgets(buf, sizeof(buf), f))
                printf("[t3] %s: %s", targets[i], buf);
            fclose(f);
        } else {
            printf("[t3] cannot open %s: %s\n", targets[i], strerror(errno));
        }
    }
    return 0;
}

