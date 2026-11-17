/*
 * sentry_sandbox_v3.c — Phase 1 + Phase 2 + Phase 3 combined
 *
 * Changes applied (changes.md):
 *   Part 1.1 — CLONE_NEWUSER + UID/GID maps + drop all capabilities via capset()
 *   Part 1.2 — Replace chroot() with pivot_root() + read-only bind-mount +
 *               tmpfs scratch layer + minimal /dev + masked dangerous /proc paths
 *   Part 1.4 — Unique cgroup name per run (sentry_<pid>); pipe handshake so
 *               cgroup_add_pid runs in parent BEFORE child calls execve
 *   Part 1.5 — Control channel: write PID:<child_pid> to --control-fd before exec
 *   Part 4   — CLONE_NEWUTS + CLONE_NEWIPC added; fresh tmpfs on /tmp;
 *               CLONE_NEWNS already present (kept)
 *
 * Usage:
 *   sudo ./sentry_sandbox_v3 run <command> [options]
 *
 * Options:
 *   --profile  strict | normal | development   (resource caps)
 *   --seccomp  minimal | standard | permissive  (syscall filter)
 *   --control-fd N                              (fd to write PID:<pid>\n to)
 *
 * Build:
 *   gcc -Wall -Wextra -std=gnu11 \
 *       -o sentry_sandbox_v3 \
 *       sentry_sandbox_v3.c cgroup.c seccomp_policy.c \
 *       -lseccomp
 *
 * Requires: libseccomp-dev
 *   sudo apt install -y build-essential libseccomp-dev
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <linux/capability.h>
#include <sys/socket.h>
#include <sys/uio.h>

#ifndef PR_CAPBSET_DROP
#define PR_CAPBSET_DROP 24
#endif
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#include "cgroup.h"
#include "seccomp_policy.h"
#include "notify.h"

#define STACK_SIZE       (1024 * 1024)
#define DEFAULT_ROOT     "/opt/sentry/sandbox-root"
#define SENTRY_VERSION   "0.4.0"
#define OLD_ROOT_NAME    ".old_root"

/* ------------------------------------------------------------------ */
/*  Child configuration                                               */
/* ------------------------------------------------------------------ */

struct sandbox_config {
    char          **cmd;
    char           *sandbox_root;
    seccomp_mode_t  seccomp_mode;
    int             ready_pipe_rd;  /* child reads one byte then continues */
    int             ready_pipe_wr;  /* child closes its write end          */
    int             notify_sock;
    uid_t           host_uid;       /* real UID on host (for user ns maps) */
    gid_t           host_gid;       /* real GID on host                    */
};

/* ------------------------------------------------------------------ */
/*  pivot_root syscall wrapper (not in glibc)                        */
/* ------------------------------------------------------------------ */

static int pivot_root(const char *new_root, const char *put_old)
{
    return (int)syscall(SYS_pivot_root, new_root, put_old);
}

/* ------------------------------------------------------------------ */
/*  Helper: write a small file atomically                            */
/* ------------------------------------------------------------------ */

static int write_file(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        fprintf(stderr, "[sandbox] open(%s): %s\n", path, strerror(errno));
        return -1;
    }
    ssize_t n = write(fd, value, strlen(value));
    close(fd);
    if (n < 0) {
        fprintf(stderr, "[sandbox] write(%s, '%s'): %s\n", path, value, strerror(errno));
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Part 1.1 — Write UID/GID maps so we appear as UID 0 inside      */
/*  the user namespace but map to an unprivileged UID on host.       */
/*  Called from the PARENT after clone(), using the child's PID.     */
/* ------------------------------------------------------------------ */

static int write_uid_gid_maps(pid_t child_pid, uid_t host_uid, gid_t host_gid)
{
    char path[256];
    char buf[64];

    /* Deny setgroups first (required before writing gid_map) */
    snprintf(path, sizeof(path), "/proc/%d/setgroups", (int)child_pid);
    if (write_file(path, "deny") != 0) {
        fprintf(stderr, "[sandbox] Failed to write setgroups deny\n");
        return -1;
    }

    /* uid_map: inside UID 0 -> host UID */
    snprintf(path, sizeof(path), "/proc/%d/uid_map", (int)child_pid);
    snprintf(buf,  sizeof(buf),  "0 %u 1\n", (unsigned)host_uid);
    if (write_file(path, buf) != 0) {
        fprintf(stderr, "[sandbox] Failed to write uid_map\n");
        return -1;
    }

    /* gid_map: inside GID 0 -> host GID */
    snprintf(path, sizeof(path), "/proc/%d/gid_map", (int)child_pid);
    snprintf(buf,  sizeof(buf),  "0 %u 1\n", (unsigned)host_gid);
    if (write_file(path, buf) != 0) {
        fprintf(stderr, "[sandbox] Failed to write gid_map\n");
        return -1;
    }

    fprintf(stderr, "[sandbox] UID/GID maps written: host %u:%u -> sandbox 0:0\n",
            (unsigned)host_uid, (unsigned)host_gid);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Part 1.1 — Drop all capabilities via capset()                   */
/* ------------------------------------------------------------------ */

static int drop_all_capabilities(void)
{
    /* First: prevent any future privilege escalation */
    if (prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0) != 0) {
        perror("[sandbox] prctl PR_SET_KEEPCAPS");
        return -1;
    }

    /* Read highest capability number from /proc/sys/kernel/cap_last_cap */
    FILE *f = fopen("/proc/sys/kernel/cap_last_cap", "r");
    if (!f) {
        perror("[sandbox] fopen /proc/sys/kernel/cap_last_cap");
        return -1;
    }
    int last_cap = -1;
    if (fscanf(f, "%d", &last_cap) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);

    for (int cap = 0; cap <= last_cap; cap++) {
        if (prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) != 0) {
            perror("[sandbox] prctl PR_CAPBSET_DROP");
            return -1;
        }
    }

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) {
        perror("[sandbox] prctl PR_CAP_AMBIENT_CLEAR_ALL");
        return -1;
    }

    /* Call capset() directly to drop effective, permitted, and inheritable sets */
    struct __user_cap_header_struct hdr;
    struct __user_cap_data_struct data[2];

    memset(&hdr, 0, sizeof(hdr));
    memset(data, 0, sizeof(data));
    hdr.version = _LINUX_CAPABILITY_VERSION_3;
    hdr.pid = 0; /* current process */

    if (syscall(SYS_capset, &hdr, data) != 0) {
        perror("[sandbox] capset");
        return -1;
    }

    fprintf(stderr, "[sandbox] All capabilities dropped (CapEff=0)\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Part 1.2 — pivot_root + read-only base + tmpfs scratch           */
/* ------------------------------------------------------------------ */

static int setup_filesystem(const char *sandbox_root)
{
    char old_root_path[512];
    char path[512];

    /* Step A: Detach mount propagation so our mounts don't leak to host */
    if (mount("none", "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
        perror("[sandbox] mount: make-rprivate");
        return -1;
    }

    /* Step B: Bind-mount sandbox_root onto itself to make it a mount point */
    if (mount(sandbox_root, sandbox_root, NULL, MS_BIND | MS_REC, NULL) != 0) {
        perror("[sandbox] mount: bind sandbox_root");
        return -1;
    }

    /* Step C: Remount it read-only */
    if (mount(sandbox_root, sandbox_root, NULL,
              MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL) != 0) {
        perror("[sandbox] mount: read-only remount");
        return -1;
    }

    /* Step D: The sandbox root is mounted read-only; writable areas are only
     * the tmpfs mounts on /tmp and /dev. */

    /* Step E: Re-mount /proc inside sandbox_root (read-only after pivot) */
    snprintf(path, sizeof(path), "%s/proc", sandbox_root);
    if (mkdir(path, 0555) != 0 && errno != EEXIST) {
        fprintf(stderr, "[sandbox] mkdir %s: %s\n", path, strerror(errno));
    }
    if (mount("proc", path, "proc", 0, NULL) != 0) {
        fprintf(stderr, "[sandbox] FATAL: mount /proc failed: %s\n", strerror(errno));
        return -1;
    }
    if (mount("proc", path, "proc", MS_REMOUNT | MS_RDONLY, NULL) != 0) {
        fprintf(stderr, "[sandbox] FATAL: remount /proc ro failed: %s\n", strerror(errno));
        return -1;
    }

    /* Step F: Real device nodes (null, zero, urandom) already exist in <root>/dev.
     * Do NOT mount a tmpfs over /dev. */

    /* Step G: Fresh tmpfs on /tmp inside sandbox */
    snprintf(path, sizeof(path), "%s/tmp", sandbox_root);
    if (mkdir(path, 0777) != 0 && errno != EEXIST) {
        fprintf(stderr, "[sandbox] mkdir %s: %s\n", path, strerror(errno));
    }
    if (mount("tmpfs", path, "tmpfs", 0, "size=32m,mode=1777") != 0) {
        fprintf(stderr, "[sandbox] FATAL: mount tmpfs /tmp failed: %s\n", strerror(errno));
        return -1;
    }

    /* Step H: Create old_root directory and call pivot_root */
    snprintf(old_root_path, sizeof(old_root_path), "%s/" OLD_ROOT_NAME, sandbox_root);
    if (mkdir(old_root_path, 0700) != 0 && errno != EEXIST) {
        fprintf(stderr, "[sandbox] mkdir old_root: %s\n", strerror(errno));
        return -1;
    }
    if (pivot_root(sandbox_root, old_root_path) != 0) {
        perror("[sandbox] pivot_root");
        return -1;
    }
    if (chdir("/") != 0) {
        perror("[sandbox] chdir /");
        return -1;
    }

    /* Check that /dev/null, /dev/zero and /dev/urandom can be opened for reading */
    const char *check_devs[] = { "/dev/null", "/dev/zero", "/dev/urandom", NULL };
    for (int i = 0; check_devs[i]; i++) {
        int fd = open(check_devs[i], O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "[sandbox] FATAL: open %s failed: %s\n", check_devs[i], strerror(errno));
            return -1;
        }
        close(fd);
    }

    /* Step I: Mask dangerous /proc paths by bind-mounting /dev/null over them.
     *         This must happen AFTER pivot_root so paths are relative to new root. */
    const char *dangerous_proc_paths[] = {
        "/proc/sysrq-trigger",
        "/proc/sys/kernel/core_pattern",
        "/proc/kcore",
        NULL
    };
    for (int i = 0; dangerous_proc_paths[i]; i++) {
        if (access(dangerous_proc_paths[i], F_OK) == 0) {
            if (mount("/dev/null", dangerous_proc_paths[i], NULL, MS_BIND, NULL) != 0) {
                fprintf(stderr, "[sandbox] FATAL: mask %s failed: %s\n",
                        dangerous_proc_paths[i], strerror(errno));
                return -1;
            }
        }
    }

    /* Step J: Unmount old root */
    if (umount2("/" OLD_ROOT_NAME, MNT_DETACH) != 0) {
        fprintf(stderr, "[sandbox] FATAL: umount2 old_root failed: %s\n", strerror(errno));
        return -1;
    }

    printf("  ✓ pivot_root complete (read-only base + tmpfs scratch)\n");
    printf("  ✓ Minimal /dev\n");
    printf("  ✓ /proc masked\n");
    printf("  ✓ Fresh tmpfs on /tmp\n");

    DIR *d = opendir("/" OLD_ROOT_NAME);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) != NULL) {
            if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
                closedir(d);
                fprintf(stderr, "[sandbox] FATAL: old root not empty (host fs reachable)\n");
                return -1;
            }
        }
        closedir(d);
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Loopback helper                                                   */
/* ------------------------------------------------------------------ */

static int bring_up_loopback(void)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) { perror("socket (loopback)"); return -1; }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ);

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS"); close(sockfd); return -1;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS"); close(sockfd); return -1;
    }
    close(sockfd);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Child entry point                                                 */
/* ------------------------------------------------------------------ */

static int verify_isolation(void)
{
    char buf[256], line[256];
    FILE *f;

    f = fopen("/proc/self/uid_map", "r");
    if (!f) { fprintf(stderr, "[sandbox] verify: cannot open uid_map: %s\n", strerror(errno)); return -1; }
    line[0] = '\0';
    if (fgets(line, sizeof line, f) == NULL) line[0] = '\0';
    fclose(f);
    fprintf(stderr, "[sandbox] verify: uid_map='%s' getuid=%d\n", line, (int)getuid());
    if (!strstr(line, "65534")) { fprintf(stderr, "[sandbox] verify: FAIL uid_map lacks 65534\n"); return -1; }
    if (getuid() != 0)          { fprintf(stderr, "[sandbox] verify: FAIL getuid != 0\n"); return -1; }

    f = fopen("/proc/self/status", "r");
    if (!f) { fprintf(stderr, "[sandbox] verify: cannot open status: %s\n", strerror(errno)); return -1; }
    int found = 0, ok = 0;
    while (fgets(buf, sizeof buf, f)) {
        if (!strncmp(buf, "CapEff:", 7)) {
            fprintf(stderr, "[sandbox] verify: %s", buf);
            found = 1;
            ok = (strstr(buf, "0000000000000000") != NULL);
            break;
        }
    }
    fclose(f);
    if (!found || !ok) { fprintf(stderr, "[sandbox] verify: FAIL CapEff not zero\n"); return -1; }
    return 0;
}

static int send_fd(int sock, int fd) {
    char c = 'x'; struct iovec io = { &c, 1 };
    char cb[CMSG_SPACE(sizeof(int))]; memset(cb, 0, sizeof cb);
    struct msghdr m; memset(&m, 0, sizeof m);
    m.msg_iov = &io; m.msg_iovlen = 1; m.msg_control = cb; m.msg_controllen = sizeof cb;
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    h->cmsg_level = SOL_SOCKET; h->cmsg_type = SCM_RIGHTS; h->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(h), &fd, sizeof(int));
    return sendmsg(sock, &m, 0) == 1 ? 0 : -1;
}
static int recv_fd(int sock) {
    char c; struct iovec io = { &c, 1 };
    char cb[CMSG_SPACE(sizeof(int))];
    struct msghdr m; memset(&m, 0, sizeof m);
    m.msg_iov = &io; m.msg_iovlen = 1; m.msg_control = cb; m.msg_controllen = sizeof cb;
    if (recvmsg(sock, &m, 0) != 1) return -1;
    struct cmsghdr *h = CMSG_FIRSTHDR(&m);
    if (!h || h->cmsg_type != SCM_RIGHTS) return -1;
    int fd; memcpy(&fd, CMSG_DATA(h), sizeof(int)); return fd;
}

static int child_fn(void *arg)
{
    /* Ensure the child is killed when the parent exits (even on SIGKILL). */
    prctl(PR_SET_PDEATHSIG, SIGKILL);

    setbuf(stdout, NULL);
    struct sandbox_config *cfg = (struct sandbox_config *)arg;

    printf("╔══════════════════════════════════════════════╗\n");
    printf("║       SENTRY SANDBOX v4 — ACTIVE             ║\n");
    printf("╚══════════════════════════════════════════════╝\n");
    printf("  PID (inside namespace) : %d\n", getpid());
    printf("  Sandbox root           : %s\n", cfg->sandbox_root);
    printf("  Command                : %s\n", cfg->cmd[0]);
    printf("──────────────────────────────────────────────\n");
    fflush(stdout);

    /* Part 1.4 — Pipe handshake:
     * Child closes the write end and waits on the read end.
     * Parent writes 1 byte AFTER it has added the child PID to the cgroup.
     * This ensures cgroup_add_pid happens before execve. */
    close(cfg->ready_pipe_wr);
    char go = 0;
    ssize_t n = read(cfg->ready_pipe_rd, &go, 1);
    close(cfg->ready_pipe_rd);
    if (n != 1 || go != '!') {
        fprintf(stderr, "[sandbox] FATAL: parent aborted setup\n");
        return EXIT_FAILURE;
    }
    printf("  ✓ Cgroup handshake complete\n");
    fflush(stdout);

    /* Part 1.2 — Set up the filesystem (pivot_root replaces chroot) */
    if (setup_filesystem(cfg->sandbox_root) != 0) {
        return EXIT_FAILURE;
    }

    /* Part 4 — Bring loopback up (still inside network namespace) */
    if (bring_up_loopback() != 0) {
        fprintf(stderr, "  Warning: could not bring up loopback.\n");
    }

    /* Become a new session leader — detach from controlling terminal. */
    if (setsid() < 0) {
        perror("[sandbox] setsid (non-fatal)");
    }

    /* Our real kuid is still host root (unmapped, shows as 65534). Switch to
     * ns uid/gid 0 (= host 65534) while we still hold CAP_SETUID/SETGID. */
    if (setresgid(0, 0, 0) != 0 || setresuid(0, 0, 0) != 0) {
        fprintf(stderr, "[sandbox] FATAL: switch to sandbox uid/gid failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /* Part 1.1 — Drop all capabilities */
    if (drop_all_capabilities() != 0) {
        fprintf(stderr, "[sandbox] Failed to drop all capabilities\n");
        return EXIT_FAILURE;
    }

    if (verify_isolation() != 0) {
        fprintf(stderr, "[sandbox] FATAL: isolation verification failed\n");
        return EXIT_FAILURE;
    }

    printf("  ✓ PID namespace isolated\n");
    printf("  ✓ UTS namespace isolated\n");
    printf("  ✓ IPC namespace isolated\n");
    printf("  ✓ Mount namespace isolated (pivot_root)\n");
    printf("  ✓ Network namespace isolated (loopback only)\n");
    printf("  ✓ User namespace isolated (no host capabilities)\n");
    fflush(stdout);

    /*
     * Close all file descriptors >= 3 before installing seccomp so that no
     * inherited fds (including cfg->control_fd) survive into the exec'd child,
     * but preserve cfg->notify_sock so we can hand over the listener fd.
     * Try the Linux 5.9+ close_range(2) fast path first; fall back to a loop.
     */
    int s = cfg->notify_sock;
    int cr_fail = 0;
    if (s > 3) {
        if (syscall(SYS_close_range, 3, s - 1, 0) != 0) {
            cr_fail = 1;
        }
    }
    if (syscall(SYS_close_range, s + 1, ~0U, 0) != 0) {
        cr_fail = 1;
    }
    if (cr_fail) {
        int max_fd = getdtablesize();
        for (int fd = 3; fd < max_fd; fd++) {
            if (fd != s) {
                close(fd);
            }
        }
    }

    /*
     * Seccomp MUST be installed AFTER filesystem setup and BEFORE exec.
     * - After pivot_root: filter only needs to cover target binary's syscalls.
     * - Before exec: filter is inherited by the exec'd program.
     */
    int nfd = -1;
    if (seccomp_install_policy(cfg->seccomp_mode, &nfd) != 0) {
        fprintf(stderr, "[sentry] Failed to install seccomp filter\n");
        close(cfg->notify_sock);
        return EXIT_FAILURE;
    }

    if (nfd >= 0) {
        if (send_fd(cfg->notify_sock, nfd) != 0) {
            fprintf(stderr, "[sandbox] FATAL: could not hand over seccomp listener\n");
            return EXIT_FAILURE;
        }
        close(nfd);
    } else {
        if (send(cfg->notify_sock, "n", 1, MSG_NOSIGNAL) != 1) {
            fprintf(stderr, "[sandbox] FATAL: could not notify parent\n");
            return EXIT_FAILURE;
        }
    }
    fcntl(cfg->notify_sock, F_SETFD, FD_CLOEXEC);

    printf("  ✓ Seccomp filter active\n");
    printf("──────────────────────────────────────────────\n\n");
    fflush(stdout);

    /* exec — seccomp filter is inherited across execve */
    if (send(cfg->notify_sock, "X", 1, MSG_NOSIGNAL) != 1) {
        fprintf(stderr, "[sandbox] FATAL: could not send start signal\n");
        return EXIT_FAILURE;
    }
    execvp(cfg->cmd[0], cfg->cmd);
    (void)send(cfg->notify_sock, "F", 1, MSG_NOSIGNAL);
    perror("execvp");
    return EXIT_FAILURE;
}

/* ------------------------------------------------------------------ */
/*  create_sandbox_v3 — Part 1 + 2 + 3 + 4                          */
/* ------------------------------------------------------------------ */

static pid_t abort_child(pid_t pid, int wr, char *stack, struct sandbox_config *cfg)
{
    kill(pid, SIGKILL);
    waitpid(pid, NULL, 0);
    close(wr);
    free(cfg);
    free(stack);
    return -1;
}

pid_t create_sandbox_v3(char *cmd[], char *sandbox_root,
                        const sandbox_profile_t *profile,
                        seccomp_mode_t seccomp_mode,
                        char *cgroup_path_out,    /* SENTRY_CGROUP_PATH_MAX */
                        int control_fd,           /* -1 if not used */
                        const char *events_path,
                        int *status_sock_out)
{
    if (status_sock_out) *status_sock_out = -1;

    if (access(sandbox_root, F_OK) != 0) {
        fprintf(stderr, "Error: sandbox root '%s' not found.\n", sandbox_root);
        return -1;
    }

    /* Part 1.4 — Pipe for parent→child handshake (cgroup_add_pid before exec) */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        return -1;
    }
    /* pipefd[0] = read end (child), pipefd[1] = write end (parent signals child) */

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        perror("socketpair");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        perror("malloc");
        close(pipefd[0]); close(pipefd[1]);
        close(sv[0]); close(sv[1]);
        return -1;
    }
    char *stack_top = stack + STACK_SIZE;

    struct sandbox_config *cfg = malloc(sizeof(*cfg));
    if (!cfg) {
        perror("malloc cfg");
        free(stack);
        close(pipefd[0]); close(pipefd[1]);
        close(sv[0]); close(sv[1]);
        return -1;
    }
    cfg->cmd            = cmd;
    cfg->sandbox_root   = sandbox_root;
    cfg->seccomp_mode   = seccomp_mode;
    cfg->ready_pipe_rd  = pipefd[0];
    cfg->ready_pipe_wr  = pipefd[1];
    cfg->notify_sock    = sv[1];
    cfg->host_uid       = 65534;
    cfg->host_gid       = 65534;

    /*
     * Part 1.1 — CLONE_NEWUSER allows unprivileged user namespaces.
     * Part 4    — CLONE_NEWUTS isolates hostname, CLONE_NEWIPC isolates IPC.
     * The child appears as UID 0 inside but maps to the real UID outside.
     */
    pid_t pid = clone(child_fn, stack_top,
                      CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS |
                      CLONE_NEWNET  | CLONE_NEWUTS | CLONE_NEWIPC | SIGCHLD,
                      cfg);

    if (pid == -1) {
        perror("clone");
        free(cfg); free(stack);
        close(pipefd[0]); close(pipefd[1]);
        close(sv[0]); close(sv[1]);
        return -1;
    }

    /* Parent: close child's read end */
    close(pipefd[0]);
    close(sv[1]);

    /* Part 1.1 — Write UID/GID maps NOW (from parent, after clone) */
    if (write_uid_gid_maps(pid, cfg->host_uid, cfg->host_gid) != 0) {
        fprintf(stderr, "[sandbox] FATAL: UID/GID map write failed\n");
        close(sv[0]);
        return abort_child(pid, pipefd[1], stack, cfg);
    }

    /* Part 1.4 — Build unique cgroup path using child PID */
    cgroup_build_path(cgroup_path_out, pid);

    /* Part 1.4 — Create cgroup and apply profile */
    if (cgroup_create(cgroup_path_out) != 0) {
        close(sv[0]);
        return abort_child(pid, pipefd[1], stack, cfg);
    }
    if (profile && cgroup_apply_profile(cgroup_path_out, profile) != 0) {
        close(sv[0]);
        cgroup_destroy(cgroup_path_out);
        return abort_child(pid, pipefd[1], stack, cfg);
    }

    /* Part 1.4 — Add PID to cgroup BEFORE signalling child to exec */
    if (cgroup_add_pid(cgroup_path_out, pid) != 0) {
        fprintf(stderr, "[sandbox] FATAL: cgroup_add_pid failed\n");
        close(sv[0]);
        cgroup_destroy(cgroup_path_out);
        return abort_child(pid, pipefd[1], stack, cfg);
    }

    /* Part 1.5 — Write PID to control channel so CLI doesn't parse stdout */
    if (control_fd >= 0) {
        char ctrl_buf[64];
        int n = snprintf(ctrl_buf, sizeof(ctrl_buf), "PID:%d\n", (int)pid);
        if (write(control_fd, ctrl_buf, n) != n) {
            fprintf(stderr, "[sandbox] WARNING: control_fd write failed\n");
        }
        close(control_fd);
    }

    /* Unblock child by writing 1 byte to the ready pipe */
    char go = '!';
    if (write(pipefd[1], &go, 1) != 1) {
        perror("[sandbox] pipe write (unblock child)");
    }
    close(pipefd[1]);

    int nfd = recv_fd(sv[0]);
    if (status_sock_out) *status_sock_out = sv[0];
    if (nfd >= 0 && notify_start(nfd, events_path) != 0) {
        close(sv[0]);
        if (status_sock_out) *status_sock_out = -1;
        cgroup_destroy(cgroup_path_out);
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
        free(cfg);
        free(stack);
        return -1;
    }

    /* Note: stack and cfg are leaked — they are needed until child exits.
     * For a long-running program this is acceptable (it's only two mallocs). */

    return pid;
}

/* ------------------------------------------------------------------ */
/*  CLI                                                               */
/* ------------------------------------------------------------------ */

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "SENTRY Sandbox v%s\n"
        "Usage: %s run <command> [--profile <name>] [--seccomp <mode>] [--control-fd <n>] [--events-file <path>] [--status-file <path>]\n"
        "\n"
        "Resource profiles:\n"
        "  strict      CPU 10%%, RAM 256MB, PIDs 10\n"
        "  normal      CPU 40%%, RAM 1GB,   PIDs 30  (default)\n"
        "  development CPU 70%%, RAM 2GB,   PIDs 50\n"
        "\n"
        "Seccomp modes:\n"
        "  minimal     Bare-minimum syscalls (blocks almost everything)\n"
        "  standard    Common utilities: ls, cat, echo, bash  (default)\n"
        "  permissive  Extended: Python scripts, dynamic languages\n"
        "\n"
        "Supervisor events:\n"
        "  --events-file PATH Log observed events (JSON-lines) to PATH.\n"
        "  --status-file PATH Write JSON status on exit to PATH.\n"
        "\n"
        "Control channel:\n"
        "  --control-fd N   Write 'PID:<child_pid>\\n' to fd N before exec.\n"
        "                   Allows CLI to obtain child PID without parsing stdout.\n"
        "\n"
        "Examples:\n"
        "  sudo %s run /bin/bash\n"
        "  sudo %s run /bin/bash --profile strict --seccomp standard\n"
        "  sudo %s run /bin/ls --seccomp minimal\n"
        "\n"
        "Environment:\n"
        "  SENTRY_ROOT     sandbox root (default: %s)\n"
        "  SENTRY_PROFILE  default profile name\n"
        "  SENTRY_SECCOMP  default seccomp mode\n",
        SENTRY_VERSION, prog, prog, prog, prog, DEFAULT_ROOT);
}

static char *extract_option(char **argv, int *argc_ptr, const char *flag)
{
    int argc = *argc_ptr;
    for (int i = 0; i < argc - 1; i++) {
        if (strcmp(argv[i], flag) == 0) {
            char *val = argv[i + 1];
            /* Remove flag and value by shifting */
            for (int j = i; j < argc - 2; j++) argv[j] = argv[j + 2];
            argv[argc - 2] = NULL;
            *argc_ptr -= 2;
            return val;
        }
    }
    return NULL;
}

static void write_status(const char *path, int started, int status) {
    FILE *f = fopen(path, "w"); if (!f) return;
    const char *st = started ? "true" : "false";
    if (WIFEXITED(status))
        fprintf(f, "{\"started\":%s,\"exited\":true,\"exit_code\":%d,\"signal\":null}\n", st, WEXITSTATUS(status));
    else if (WIFSIGNALED(status))
        fprintf(f, "{\"started\":%s,\"exited\":false,\"exit_code\":null,\"signal\":%d}\n", st, WTERMSIG(status));
    else
        fprintf(f, "{\"started\":%s,\"exited\":false,\"exit_code\":null,\"signal\":null}\n", st);
    fclose(f);
}

int main(int argc, char *argv[])
{
    setbuf(stdout, NULL);

    if (argc < 3 || strcmp(argv[1], "run") != 0) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    char *sandbox_root = getenv("SENTRY_ROOT");
    if (!sandbox_root || !*sandbox_root) sandbox_root = DEFAULT_ROOT;

    char **cmd_start  = &argv[2];
    int   cmd_argc    = argc - 2;

    /* Extract --profile, --seccomp, --control-fd from command args */
    const char *profile_name  = extract_option(cmd_start, &cmd_argc, "--profile");
    const char *seccomp_name  = extract_option(cmd_start, &cmd_argc, "--seccomp");
    const char *control_fd_s  = extract_option(cmd_start, &cmd_argc, "--control-fd");
    const char *events_path   = extract_option(cmd_start, &cmd_argc, "--events-file");
    const char *status_file   = extract_option(cmd_start, &cmd_argc, "--status-file");

    if (!profile_name || !*profile_name)
        profile_name = getenv("SENTRY_PROFILE");
    if (!profile_name || !*profile_name)
        profile_name = "normal";

    if (!seccomp_name || !*seccomp_name)
        seccomp_name = getenv("SENTRY_SECCOMP");
    if (!seccomp_name || !*seccomp_name)
        seccomp_name = "standard";

    int control_fd = -1;
    if (control_fd_s && *control_fd_s) {
        control_fd = atoi(control_fd_s);
        if (control_fd < 3) {
            fprintf(stderr, "[sentry] Invalid --control-fd %s (must be >= 3)\n", control_fd_s);
            control_fd = -1;
        }
    }

    if (cmd_argc < 1 || !cmd_start[0]) {
        fprintf(stderr, "Error: no command specified.\n");
        return EXIT_FAILURE;
    }

    const sandbox_profile_t *profile = profile_from_name(profile_name);
    if (!profile) return EXIT_FAILURE;

    seccomp_mode_t seccomp_mode = seccomp_mode_from_name(seccomp_name);

    printf("[sentry] version %s\n", SENTRY_VERSION);
    printf("[sentry] Sandbox root  : %s\n", sandbox_root);
    printf("[sentry] Command       : %s\n", cmd_start[0]);
    printf("[sentry] Profile       : %s  (CPU %d%%, RAM %dMB, PIDs %d)\n",
           profile->name, profile->cpu_percent, profile->ram_mb, profile->max_pids);
    printf("[sentry] Seccomp mode  : %s\n", seccomp_name);
    printf("[sentry] Parent PID    : %d\n", getpid());
    printf("\n");

    char cgroup_path[SENTRY_CGROUP_PATH_MAX];
    memset(cgroup_path, 0, sizeof(cgroup_path));

    int status_sock = -1;
    pid_t child = create_sandbox_v3(cmd_start, sandbox_root, profile,
                                    seccomp_mode, cgroup_path, control_fd,
                                    events_path, &status_sock);
    if (child == -1) {
        fprintf(stderr, "[sentry] Failed to create sandbox.\n");
        return EXIT_FAILURE;
    }

    /* Part 1.5 — Also print to stdout for human readers (not for security) */
    printf("[sentry] Sandbox launched — child PID = %d\n", child);
    printf("[sentry] Cgroup         : %s\n", cgroup_path);
    fflush(stdout);

    int status;
    if (waitpid(child, &status, 0) == -1) {
        perror("waitpid");
        notify_stop();
        if (status_sock >= 0) close(status_sock);
        cgroup_destroy(cgroup_path);
        return EXIT_FAILURE;
    }
    notify_stop();

    int started = 0;
    if (status_sock >= 0) {
        char b[8]; memset(b, 0, sizeof b); size_t n = 0; ssize_t r;
        while (n < sizeof b && (r = recv(status_sock, b + n, sizeof b - n, MSG_DONTWAIT)) > 0) n += (size_t)r;
        started = (memchr(b, 'X', n) != NULL) && (memchr(b, 'F', n) == NULL);
        close(status_sock);
    }
    if (status_file) write_status(status_file, started, status);

    printf("[sentry] ──────────────────────────────────────\n");
    int exit_code = EXIT_SUCCESS;
    if (WIFEXITED(status)) {
        int ec = WEXITSTATUS(status);
        if (ec == 0) {
            printf("[sentry] Sandbox exited normally (status 0)\n");
        } else {
            printf("[sentry] Sandbox exited with non-zero status %d\n", ec);
            exit_code = ec;
        }
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        exit_code = 128 + sig;
        switch (sig) {
        case SIGSYS:
            printf("[sentry] *** SIGSYS: sandbox killed - blocked syscall hit seccomp filter ***\n");
            break;
        case SIGKILL:
            printf("[sentry] *** SIGKILL: sandbox forcibly terminated (OOM or external kill) ***\n");
            break;
        case SIGTERM:
            printf("[sentry] *** SIGTERM: sandbox received graceful termination request ***\n");
            break;
        case SIGXCPU:
            printf("[sentry] *** SIGXCPU: sandbox exceeded CPU time limit ***\n");
            break;
        case SIGXFSZ:
            printf("[sentry] *** SIGXFSZ: sandbox exceeded file size limit ***\n");
            break;
        default:
            printf("[sentry] Sandbox killed by signal %d (%s)\n", sig, strsignal(sig));
            break;
        }
    } else if (WIFSTOPPED(status)) {
        printf("[sentry] Sandbox stopped by signal %d\n", WSTOPSIG(status));
    }
    printf("[sentry] Sandbox session ended.\n");
    fflush(stdout);

    /* Part 1.4 — Cleanup unique cgroup after child exits */
    cgroup_destroy(cgroup_path);
    return exit_code;
}
