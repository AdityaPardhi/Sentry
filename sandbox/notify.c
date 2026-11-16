/*
 * notify.c - seccomp user-notification supervisor.
 *
 * The sandboxed program's socket(AF_INET/INET6/PACKET/NETLINK) and open*()
 * calls are routed here by the seccomp filter (SCMP_ACT_NOTIFY). We
 *   - answer every network socket() with EAFNOSUPPORT (still denied) and LOG it,
 *   - LOG opens of credential-like paths, then let the open continue
 *     (the read-only sandbox root and dropped capabilities still apply; the
 *      log is evidence only, we make no security decision on it).
 * Every notification MUST be answered or the target blocks forever.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/seccomp.h>

#include "notify.h"

#ifndef SECCOMP_USER_NOTIF_FLAG_CONTINUE
#define SECCOMP_USER_NOTIF_FLAG_CONTINUE (1UL << 0)
#endif

#define MAX_EVENTS  200
#define MAX_SEEN    64
#define PATH_BUF    256

static pthread_t       g_thread;
static int             g_started;
static volatile int    g_stop;
static int             g_fd = -1;
static FILE           *g_log;
static int             g_events;
static char            g_seen[MAX_SEEN][PATH_BUF];
static int             g_nseen;

static const char *SENSITIVE[] = {
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/master.passwd",
    ".ssh/", "id_rsa", "id_ed25519", "authorized_keys",
    ".aws/credentials", ".gnupg", NULL
};

static int is_sensitive(const char *p)
{
    for (int i = 0; SENSITIVE[i]; i++)
        if (strstr(p, SENSITIVE[i])) return 1;
    return 0;
}

static int already_seen(const char *p)
{
    for (int i = 0; i < g_nseen; i++)
        if (strcmp(g_seen[i], p) == 0) return 1;
    if (g_nseen < MAX_SEEN) {
        snprintf(g_seen[g_nseen], PATH_BUF, "%s", p);
        g_nseen++;
    }
    return 0;
}

static void sanitize(char *s)
{
    for (; *s; s++)
        if (*s == '"' || *s == '\\' || (unsigned char)*s < 0x20 || (unsigned char)*s > 0x7e)
            *s = '?';
}

static void log_line(const char *line)
{
    if (!g_log || g_events >= MAX_EVENTS) return;
    fputs(line, g_log);
    fputc('\n', g_log);
    fflush(g_log);
    g_events++;
}

/* Read a NUL-terminated string from the target's memory (best effort). */
static int read_target_str(pid_t pid, unsigned long long addr, char *out, size_t n)
{
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/mem", (int)pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    size_t len = 4096 - (size_t)(addr % 4096);   /* stay within one page */
    if (len > n - 1) len = n - 1;
    ssize_t r = pread(fd, out, len, (off_t)addr);
    close(fd);
    if (r <= 0) return -1;
    out[r] = '\0';
    sanitize(out);
    return 0;
}

static void *loop(void *arg)
{
    (void)arg;
    struct seccomp_notif      *req  = NULL;
    struct seccomp_notif_resp *resp = NULL;
    if (seccomp_notify_alloc(&req, &resp) != 0) return NULL;

    int nr_open    = seccomp_syscall_resolve_name("open");
    int nr_openat  = seccomp_syscall_resolve_name("openat");
    int nr_openat2 = seccomp_syscall_resolve_name("openat2");
    int nr_socket  = seccomp_syscall_resolve_name("socket");

    while (!g_stop) {
        struct pollfd pfd = { .fd = g_fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 200);
        if (pr < 0) { if (errno == EINTR) continue; break; }
        if (pr == 0) continue;
        if (!(pfd.revents & POLLIN)) break;          /* HUP/ERR: target is gone */

        memset(req, 0, sizeof(*req));
        int rc = seccomp_notify_receive(g_fd, req);
        if (rc == -EINTR || rc == -ENOENT) continue;
        if (rc != 0) break;

        memset(resp, 0, sizeof(*resp));
        resp->id = req->id;
        int nr = req->data.nr;

        if (nr == nr_socket) {
            char line[200];
            snprintf(line, sizeof line,
                     "{\"type\":\"network\",\"family\":%d,\"sock_type\":%d,\"pid\":%d}",
                     (int)req->data.args[0], (int)(req->data.args[1] & 0xf), (int)req->pid);
            log_line(line);
            resp->error = -EAFNOSUPPORT;             /* still denied */
        } else {
            if (nr == nr_open || nr == nr_openat || nr == nr_openat2) {
                int idx = (nr == nr_open) ? 0 : 1;
                char path[PATH_BUF];
                if (read_target_str(req->pid, req->data.args[idx], path, sizeof path) == 0 &&
                    is_sensitive(path) && !already_seen(path) &&
                    seccomp_notify_id_valid(g_fd, req->id) == 0) {
                    char line[PATH_BUF + 64];
                    snprintf(line, sizeof line,
                             "{\"type\":\"sensitive_open\",\"path\":\"%s\",\"pid\":%d}",
                             path, (int)req->pid);
                    log_line(line);
                }
            }
            resp->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
        }

        rc = seccomp_notify_respond(g_fd, resp);
        if (rc != 0 && rc != -ENOENT && rc != -EINTR) break;
    }
    seccomp_notify_free(req, resp);
    return NULL;
}

int notify_start(int notify_fd, const char *events_path)
{
    if (notify_fd < 0) return -1;
    g_fd = notify_fd;
    g_stop = 0;
    g_events = 0;
    g_nseen = 0;
    g_log = events_path ? fopen(events_path, "w") : NULL;
    if (pthread_create(&g_thread, NULL, loop, NULL) != 0) {
        if (g_log) { fclose(g_log); g_log = NULL; }
        close(g_fd); g_fd = -1;
        return -1;
    }
    g_started = 1;
    return 0;
}

void notify_stop(void)
{
    if (!g_started) return;
    g_stop = 1;
    pthread_join(g_thread, NULL);
    g_started = 0;
    if (g_fd >= 0) { close(g_fd); g_fd = -1; }
    if (g_log) { fclose(g_log); g_log = NULL; }
}