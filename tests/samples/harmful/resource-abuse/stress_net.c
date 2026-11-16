/*
 * stress_net.c — SENTRY Phase 6 Network Activity Stress Test
 *
 * Generates rapid outbound TCP connection attempts to test SENTRY's
 * network connection rate tracking and destination logging.
 *
 * Works even when isolated in a network namespace (Phase 1.3):
 * non-blocking connect() calls create sockets in SYN_SENT or immediately
 * trigger ECONNREFUSED/ENETUNREACH, generating observable socket events.
 *
 * Usage:
 *     ./stress_net [count] [base_port]
 * Example:
 *     ./stress_net 30 8080
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define DEFAULT_COUNT 25
#define DEFAULT_PORT  9000

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);

    int count = (argc > 1) ? atoi(argv[1]) : DEFAULT_COUNT;
    int base_port = (argc > 2) ? atoi(argv[2]) : DEFAULT_PORT;
    if (count <= 0) count = DEFAULT_COUNT;

    printf("[stress_net] Initiating %d connection attempts starting at port %d...\n",
           count, base_port);

    int *fds = malloc(sizeof(int) * count);
    if (!fds) {
        perror("malloc");
        return EXIT_FAILURE;
    }

    struct timespec start_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    int attempts = 0;

    /* Create a local listener so connection attempts in the isolated netns complete handshake */
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd >= 0) {
        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in srv;
        memset(&srv, 0, sizeof(srv));
        srv.sin_family = AF_INET;
        srv.sin_port = htons(base_port);
        srv.sin_addr.s_addr = inet_addr("127.0.0.1");
        bind(server_fd, (struct sockaddr *)&srv, sizeof(srv));
        listen(server_fd, 128);
    }

    for (int i = 0; i < count; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            perror("socket");
            continue;
        }

        /* Set non-blocking */
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        struct sockaddr_in sin;
        memset(&sin, 0, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(base_port);
        sin.sin_addr.s_addr = inet_addr("127.0.0.1");

        connect(fd, (struct sockaddr *)&sin, sizeof(sin));
        fds[i] = fd;
        attempts++;

        /* Small pacing delay (20ms) to ensure monitoring intervals catch socket states */
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 20 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }

    /* Keep sockets active to allow live telemetry polling */
    struct timespec hold = { .tv_sec = 2, .tv_nsec = 500 * 1000 * 1000 };
    nanosleep(&hold, NULL);

    /* Close sockets */
    for (int i = 0; i < count; i++) {
        if (fds[i] >= 0) {
            close(fds[i]);
        }
    }
    if (server_fd >= 0) {
        close(server_fd);
    }
    free(fds);

    clock_gettime(CLOCK_MONOTONIC, &end_time);
    double elapsed = (end_time.tv_sec - start_time.tv_sec) +
                     (end_time.tv_nsec - start_time.tv_nsec) / 1e9;

    printf("[stress_net] Finished: %d connection attempts generated in %.2f seconds.\n",
           attempts, elapsed);

    return EXIT_SUCCESS;
}
