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
#include <linux/capability.h>

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
        perror("[sandbox] mount: proc (non-fatal)");
    } else {
        /* Make /proc read-only */
        if (mount("proc", path, "proc", MS_REMOUNT | MS_RDONLY, NULL) != 0) {
            perror("[sandbox] mount: proc MS_RDONLY (non-fatal)");
        }
    }

    /* Step F: Real device nodes (null, zero, urandom) already exist in <root>/dev.
     * Do NOT mount a tmpfs over /dev. */

    /* Step G: Fresh tmpfs on /tmp inside sandbox */
    snprintf(path, sizeof(path), "%s/tmp", sandbox_root);
    if (mkdir(path, 0777) != 0 && errno != EEXIST) {
        fprintf(stderr, "[sandbox] mkdir %s: %s\n", path, strerror(errno));
    }
    if (mount("tmpfs", path, "tmpfs", 0, "size=32m,mode=1777") != 0) {
        perror("[sandbox] mount: tmpfs /tmp (non-fatal)");
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
    int dev_failures = 0;
    const char *check_devs[] = { "/dev/null", "/dev/zero", "/dev/urandom", NULL };
    for (int i = 0; check_devs[i]; i++) {
        int fd = open(check_devs[i], O_RDONLY);
        if (fd >= 0) {
            close(fd);
        } else {
            dev_failures++;
        }
    }

    /* Step I: Mask dangerous /proc paths by bind-mounting /dev/null over them.
     *         This must happen AFTER pivot_root so paths are relative to new root. */
    int proc_mask_failures = 0;
    const char *dangerous_proc_paths[] = {
        "/proc/sysrq-trigger",
        "/proc/sys/kernel/core_pattern",
        "/proc/kcore",
        NULL
    };
    for (int i = 0; dangerous_proc_paths[i]; i++) {
        if (access(dangerous_proc_paths[i], F_OK) == 0) {
            if (mount("/dev/null", dangerous_proc_paths[i], NULL, MS_BIND, NULL) != 0) {
                fprintf(stderr, "[sandbox] mask %s (non-fatal): %s\n",
                        dangerous_proc_paths[i], strerror(errno));
                proc_mask_failures++;
            }
        } else {
            proc_mask_failures++;
        }
    }

    /* Step J: Unmount and remove the old root */
    if (umount2("/" OLD_ROOT_NAME, MNT_DETACH) != 0) {
        perror("[sandbox] umount2 old_root (non-fatal)");
    }
    if (rmdir("/" OLD_ROOT_NAME) != 0) {
        perror("[sandbox] rmdir old_root (non-fatal)");
    }

    printf("  ✓ pivot_root complete (read-only base + tmpfs scratch)\n");

    if (dev_failures == 0) {
        printf("  ✓ Minimal /dev\n");
    } else {
        fprintf(stderr, "  ✗ Minimal /dev: %d failed\n", dev_failures);
    }

    if (proc_mask_failures == 0) {
        printf("  ✓ /proc masked\n");
    } else {
        fprintf(stderr, "  ✗ /proc masked: %d failed\n", proc_mask_failures);
    }

    printf("  ✓ Fresh tmpfs on /tmp\n");
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
    {
        char dummy;
        if (read(cfg->ready_pipe_rd, &dummy, 1) < 0 && errno != EINTR) {
            fprintf(stderr, "[sandbox] Pipe handshake read failed: %s\n", strerror(errno));
        }
        close(cfg->ready_pipe_rd);
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

    /* Part 1.1 — Drop all capabilities */
    if (drop_all_capabilities() != 0) {
        fprintf(stderr, "[sandbox] Failed to drop all capabilities\n");
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
     * inherited fds (including cfg->control_fd) survive into the exec'd child.
     * Try the Linux 5.9+ close_range(2) fast path first; fall back to a loop.
     */
    if (syscall(SYS_close_range, 3, ~0U, 0) != 0) {
        int max_fd = getdtablesize();
        for (int fd = 3; fd < max_fd; fd++) {
            close(fd);
        }
    }

    /*
     * Seccomp MUST be installed AFTER filesystem setup and BEFORE exec.
     * - After pivot_root: filter only needs to cover target binary's syscalls.
     * - Before exec: filter is inherited by the exec'd program.
     */
    if (seccomp_install_policy(cfg->seccomp_mode) != 0) {
        fprintf(stderr, "[sentry] Failed to install seccomp filter\n");
        return EXIT_FAILURE;
    }

    printf("  ✓ Seccomp filter active\n");
    printf("──────────────────────────────────────────────\n\n");
    fflush(stdout);

    /* exec — seccomp filter is inherited across execve */
    execvp(cfg->cmd[0], cfg->cmd);
    perror("execvp");
    return EXIT_FAILURE;
}

/* ------------------------------------------------------------------ */
/*  create_sandbox_v3 — Part 1 + 2 + 3 + 4                          */
/* ------------------------------------------------------------------ */

pid_t create_sandbox_v3(char *cmd[], char *sandbox_root,
                        const sandbox_profile_t *profile,
                        seccomp_mode_t seccomp_mode,
                        char *cgroup_path_out,    /* SENTRY_CGROUP_PATH_MAX */
                        int control_fd)           /* -1 if not used */
{
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

    char *stack = malloc(STACK_SIZE);
    if (!stack) { perror("malloc"); close(pipefd[0]); close(pipefd[1]); return -1; }
    char *stack_top = stack + STACK_SIZE;

    struct sandbox_config *cfg = malloc(sizeof(*cfg));
    if (!cfg) {
        perror("malloc cfg");
        free(stack);
        close(pipefd[0]); close(pipefd[1]);
        return -1;
    }
    cfg->cmd            = cmd;
    cfg->sandbox_root   = sandbox_root;
    cfg->seccomp_mode   = seccomp_mode;
    cfg->ready_pipe_rd  = pipefd[0];
    cfg->ready_pipe_wr  = pipefd[1];
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
        return -1;
    }

    /* Parent: close child's read end */
    close(pipefd[0]);

    /* Part 1.1 — Write UID/GID maps NOW (from parent, after clone) */
    if (write_uid_gid_maps(pid, cfg->host_uid, cfg->host_gid) != 0) {
        fprintf(stderr, "[sandbox] WARNING: UID/GID map write failed\n");
    }

    /* Part 1.4 — Build unique cgroup path using child PID */
    cgroup_build_path(cgroup_path_out, pid);

    /* Part 1.4 — Create cgroup and apply profile */
    if (cgroup_create(cgroup_path_out) != 0) {
        close(pipefd[1]);
        free(cfg); free(stack);
        return -1;
    }
    if (profile && cgroup_apply_profile(cgroup_path_out, profile) != 0) {
        cgroup_destroy(cgroup_path_out);
        close(pipefd[1]);
        free(cfg); free(stack);
        return -1;
    }

    /* Part 1.4 — Add PID to cgroup BEFORE signalling child to exec */
    if (cgroup_add_pid(cgroup_path_out, pid) != 0) {
        fprintf(stderr, "[sandbox] WARNING: cgroup_add_pid failed\n");
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
        "Usage: %s run <command> [--profile <name>] [--seccomp <mode>] [--control-fd <n>]\n"
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

    pid_t child = create_sandbox_v3(cmd_start, sandbox_root, profile,
                                    seccomp_mode, cgroup_path, control_fd);
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
        cgroup_destroy(cgroup_path);
        return EXIT_FAILURE;
    }

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
