/*
 * raw_socket.c — Tries to create a raw AF_INET socket.
 * Should be blocked by seccomp (AF_INET blocked in socket() rules).
 * Expected result: SIGSYS or EAFNOSUPPORT → exit non-zero.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void)
{
    /* Attempt 1: raw AF_INET socket (would allow packet sniffing/injection) */
    int fd = socket(AF_INET, SOCK_RAW, 0);
    if (fd < 0) {
        fprintf(stderr, "[escape] socket(AF_INET, SOCK_RAW): %s — blocked\n", strerror(errno));
    } else {
        close(fd);
        fprintf(stderr, "[escape] socket(AF_INET, SOCK_RAW) SUCCEEDED — escape!\n");
        return 0;  /* escape — test FAIL */
    }

    /* Attempt 2: plain AF_INET TCP socket */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[escape] socket(AF_INET, SOCK_STREAM): %s — blocked\n", strerror(errno));
    } else {
        close(fd);
        fprintf(stderr, "[escape] socket(AF_INET, SOCK_STREAM) SUCCEEDED — escape!\n");
        return 0;  /* escape — test FAIL */
    }

    /* Attempt 3: AF_INET6 socket */
    fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        fprintf(stderr, "[escape] socket(AF_INET6): %s — blocked\n", strerror(errno));
    } else {
        close(fd);
        fprintf(stderr, "[escape] socket(AF_INET6) SUCCEEDED — escape!\n");
        return 0;  /* escape — test FAIL */
    }

    fprintf(stderr, "[escape] All raw/inet socket attempts blocked.\n");
    return 1;
}
