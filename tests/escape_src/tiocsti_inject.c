#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <errno.h>
#include <string.h>

int main(void)
{
    /* Try TIOCSTI (terminal injection) and TIOCSCTTY */
    int r1 = ioctl(0, TIOCSTI, "x");
    int r2 = ioctl(0, TIOCSCTTY, 0);

    if (r1 == 0 || r2 == 0) {
        fprintf(stderr, "[escape] ioctl terminal injection succeeded — escape!\n");
        return 0;
    }

    fprintf(stderr, "[escape] ioctl TIOCSTI/TIOCSCTTY blocked (%s) — blocked\n",
            strerror(errno));
    return 1;
}
