/*
 * test_seccomp_block.c — Step 3.2: prove that a blocked syscall is killed
 *
 * This program deliberately calls socket(AF_INET, ...) which is blocked
 * in SECCOMP_MODE_MINIMAL.  When run inside the sandbox with --seccomp minimal
 * it must be killed with SIGSYS.  When run WITHOUT the seccomp filter (or
 * with --seccomp permissive) it should succeed or fail only with EACCES.
 *
 * This is the "before/after" demonstration required by plan Step 3.2.
 *
 * Build:  gcc -O0 -o test_seccomp_block test_seccomp_block.c
 * Usage:  ./test_seccomp_block
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <errno.h>

int main(void)
{
    printf("[test_seccomp_block] PID = %d\n", getpid());
    printf("[test_seccomp_block] Attempting socket(AF_INET, SOCK_STREAM, 0)...\n");
    fflush(stdout);

    /*
     * socket() with AF_INET is NOT in SECCOMP_MODE_MINIMAL's allow-list.
     * If the seccomp filter is active, the process will be killed here
     * with SIGSYS before this line even returns.
     *
     * Without the filter the call may succeed or fail with EACCES/EPERM
     * depending on network namespace restrictions.
     */
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        /*
         * If we reach here, the kernel allowed the syscall but it
         * returned an error (e.g. EACCES, EPERM, ENETDOWN).
         * This means the seccomp filter was NOT active (or the socket
         * family is in the allow-list).
         */
        printf("[test_seccomp_block] socket() returned error: %s (errno %d)\n",
               strerror(errno), errno);
        printf("[test_seccomp_block] Seccomp filter was NOT blocking this syscall.\n");
        return 1;
    }

    printf("[test_seccomp_block] socket() succeeded — fd = %d\n", fd);
    printf("[test_seccomp_block] Seccomp filter was NOT active for this call.\n");
    close(fd);
    return 0;
}
