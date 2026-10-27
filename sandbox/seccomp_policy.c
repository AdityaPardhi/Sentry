/*
 * seccomp_policy.c — Phase 3: seccomp syscall allow-list implementation
 *
 * Changes applied (changes.md Part 1.3):
 *   - socket(): now only allows AF_UNIX (domain == 1); AF_INET/INET6/NETLINK blocked.
 *   - Removed setuid, setgid, setreuid, setregid, setresuid, setresgid, capset
 *     from the allow-list (STANDARD mode). getresuid/getresgid kept (read-only, safe).
 *   - Removed mknod and mknodat from PERMISSIVE mode.
 *   - clone/clone3: added flag check that blocks CLONE_NEWUSER (0x10000000)
 *     via SCMP_CMP_MASKED_EQ, to prevent namespace escape inside the sandbox.
 *   - Removed memfd_create from STANDARD mode.
 *   - Default action: SCMP_ACT_TRAP in DEBUG builds (syscall visible for testing),
 *     SCMP_ACT_KILL_PROCESS in release builds.
 *
 * Uses libseccomp's high-level API instead of hand-rolling BPF bytecode.
 *
 * How it works:
 *   1. seccomp_init(default_action) — set default action for unlisted syscalls.
 *   2. seccomp_rule_add(..., SCMP_ACT_ALLOW, ...) — whitelist each needed syscall.
 *   3. seccomp_load(ctx) — install the compiled BPF program via prctl().
 *
 * Requires: libseccomp-dev  (sudo apt install libseccomp-dev)
 * Link:     -lseccomp
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/prctl.h>

#include <seccomp.h>

#include "seccomp_policy.h"

/* ------------------------------------------------------------------ */
/*  Helper macros                                                     */
/* ------------------------------------------------------------------ */

#define ALLOW(ctx, syscall_name) \
    do { \
        int _r = seccomp_rule_add((ctx), SCMP_ACT_ALLOW, SCMP_SYS(syscall_name), 0); \
        if (_r != 0) { \
            fprintf(stderr, "[seccomp] Failed to allow %s: %s\n", \
                    #syscall_name, strerror(-_r)); \
            seccomp_release(ctx); \
            return -1; \
        } \
    } while (0)

/* Allow syscall only when argument at index arg_idx equals arg_val */
#define ALLOW_ARG(ctx, syscall_name, arg_idx, cmp, arg_val) \
    do { \
        int _r = seccomp_rule_add((ctx), SCMP_ACT_ALLOW, SCMP_SYS(syscall_name), 1, \
                                  SCMP_A##arg_idx((cmp), (scmp_datum_t)(arg_val))); \
        if (_r != 0) { \
            fprintf(stderr, "[seccomp] Failed to allow %s(arg%d=%lu): %s\n", \
                    #syscall_name, (arg_idx), (unsigned long)(arg_val), strerror(-_r)); \
            seccomp_release(ctx); \
            return -1; \
        } \
    } while (0)

/* Block socket() with a specific domain by returning EPERM */
#define BLOCK_SOCKET_DOMAIN(ctx, domain) \
    do { \
        int _r = seccomp_rule_add((ctx), SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1, \
                                  SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)(domain))); \
        if (_r != 0) { \
            fprintf(stderr, "[seccomp] Failed to block socket domain %d: %s\n", \
                    (domain), strerror(-_r)); \
            seccomp_release(ctx); \
            return -1; \
        } \
    } while (0)

/* ------------------------------------------------------------------ */
/*  socket() restriction helper                                       */
/*                                                                    */
/*  We want: allow socket(AF_UNIX, ...) and block everything else.   */
/*  seccomp rules are additive first-match-wins when ordered.        */
/*  Strategy: explicitly DENY the dangerous families, then allow     */
/*  the unconditional socket() rule for AF_UNIX.                     */
/* ------------------------------------------------------------------ */

/* AF_* values (same on all Linux architectures) */
#define AF_UNIX_VAL     1
#define AF_INET_VAL     2
#define AF_INET6_VAL    10
#define AF_NETLINK_VAL  16
#define AF_PACKET_VAL   17

static int allow_unix_socket_only(scmp_filter_ctx ctx)
{
    /* Block dangerous address families with EAFNOSUPPORT */
    int blocked_afs[] = { AF_INET_VAL, AF_INET6_VAL, AF_NETLINK_VAL, AF_PACKET_VAL, -1 };
    for (int i = 0; blocked_afs[i] != -1; i++) {
        int _r = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EAFNOSUPPORT), SCMP_SYS(socket), 1,
                                  SCMP_A0(SCMP_CMP_EQ, (scmp_datum_t)blocked_afs[i]));
        if (_r != 0) {
            fprintf(stderr, "[seccomp] Failed to block socket(AF=%d): %s\n",
                    blocked_afs[i], strerror(-_r));
            seccomp_release(ctx);
            return -1;
        }
    }
    /* Allow AF_UNIX only */
    ALLOW_ARG(ctx, socket, 0, SCMP_CMP_EQ, AF_UNIX_VAL);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  clone/clone3 restriction: block CLONE_NEWUSER flag               */
/* ------------------------------------------------------------------ */

#define CLONE_NEWUSER_FLAG  0x10000000UL

static int restrict_clone(scmp_filter_ctx ctx)
{
    /* Block clone() if CLONE_NEWUSER bit is set in flags (arg 0) */
    int _r = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
                              SCMP_A0(SCMP_CMP_MASKED_EQ,
                                      (scmp_datum_t)CLONE_NEWUSER_FLAG,
                                      (scmp_datum_t)CLONE_NEWUSER_FLAG));
    if (_r != 0) {
        fprintf(stderr, "[seccomp] Failed to restrict clone CLONE_NEWUSER: %s\n", strerror(-_r));
        seccomp_release(ctx);
        return -1;
    }

    /* Block clone3() similarly — its flags are in a struct pointer (arg 0),
     * so we can't inspect them easily. Block clone3 entirely for safety. */
    _r = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0);
    if (_r != 0) {
        fprintf(stderr, "[seccomp] Failed to block clone3: %s\n", strerror(-_r));
        seccomp_release(ctx);
        return -1;
    }

    /* Allow clone() without CLONE_NEWUSER (default allow will cover it after deny) */
    ALLOW(ctx, clone);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Mode: MINIMAL (Step 3.1)                                          */
/*                                                                    */
/*  Bare-bones allow-list — enough for a trivial static binary or     */
/*  the test in Step 3.2.  Blocks almost everything.                  */
/* ------------------------------------------------------------------ */

static int install_minimal(scmp_filter_ctx ctx)
{
    ALLOW(ctx, read);
    ALLOW(ctx, write);
    ALLOW(ctx, openat);
    ALLOW(ctx, close);
    ALLOW(ctx, fstat);
    ALLOW(ctx, mmap);
    ALLOW(ctx, mprotect);
    ALLOW(ctx, munmap);
    ALLOW(ctx, brk);
    ALLOW(ctx, exit);
    ALLOW(ctx, exit_group);
    ALLOW(ctx, arch_prctl);
    ALLOW(ctx, set_tid_address);
    ALLOW(ctx, set_robust_list);
    ALLOW(ctx, execve);
    ALLOW(ctx, getpid);
    ALLOW(ctx, rt_sigaction);
    ALLOW(ctx, rt_sigprocmask);
    ALLOW(ctx, rt_sigreturn);
    ALLOW(ctx, rseq);
    ALLOW(ctx, getrandom);

    printf("[seccomp] Mode: MINIMAL (%d syscalls allowed)\n", 21);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Mode: STANDARD (Step 3.3)                                         */
/*                                                                    */
/*  Sufficient to run: ls, cat, echo, grep, ps, find, bash           */
/*  Blocks: ptrace, mount, reboot, raw sockets, bpf, kexec, etc.     */
/* ------------------------------------------------------------------ */

static int install_standard(scmp_filter_ctx ctx)
{
    /* Basic I/O */
    ALLOW(ctx, read);
    ALLOW(ctx, write);
    ALLOW(ctx, pread64);
    ALLOW(ctx, pwrite64);
    ALLOW(ctx, readv);
    ALLOW(ctx, writev);
    ALLOW(ctx, copy_file_range);
    ALLOW(ctx, sendfile);
    ALLOW(ctx, splice);
    ALLOW(ctx, tee);

    /* File operations */
    ALLOW(ctx, open);
    ALLOW(ctx, openat);
    ALLOW(ctx, close);
    ALLOW(ctx, stat);
    ALLOW(ctx, fstat);
    ALLOW(ctx, lstat);
    ALLOW(ctx, newfstatat);
    ALLOW(ctx, statx);
    ALLOW(ctx, access);
    ALLOW(ctx, faccessat);
    ALLOW(ctx, faccessat2);
    ALLOW(ctx, lseek);
    ALLOW(ctx, getdents64);
    ALLOW(ctx, getcwd);
    ALLOW(ctx, readlink);
    ALLOW(ctx, readlinkat);
    /* read-only: lets ls -l list xattrs */
    ALLOW(ctx, listxattr);
    ALLOW(ctx, llistxattr);
    ALLOW(ctx, flistxattr);
    ALLOW(ctx, fcntl);
    ALLOW(ctx, ioctl);
    ALLOW(ctx, umask);
    ALLOW(ctx, statfs);
    ALLOW(ctx, fstatfs);
    ALLOW(ctx, chdir);
    ALLOW(ctx, fchdir);
    ALLOW(ctx, mkdir);
    ALLOW(ctx, mkdirat);
    ALLOW(ctx, rmdir);
    ALLOW(ctx, unlink);
    ALLOW(ctx, unlinkat);
    ALLOW(ctx, rename);
    ALLOW(ctx, renameat);
    ALLOW(ctx, renameat2);

    /* Memory */
    ALLOW(ctx, mmap);
    ALLOW(ctx, mprotect);
    ALLOW(ctx, munmap);
    ALLOW(ctx, mremap);
    ALLOW(ctx, brk);
    ALLOW(ctx, madvise);
    /* memfd_create removed — Part 1.3 */

    /* Process management */
    ALLOW(ctx, execve);
    ALLOW(ctx, execveat);
    ALLOW(ctx, exit);
    ALLOW(ctx, exit_group);
    /* clone/clone3: block CLONE_NEWUSER, allow the rest */
    if (restrict_clone(ctx) != 0) return -1;
    ALLOW(ctx, fork);
    ALLOW(ctx, vfork);
    ALLOW(ctx, wait4);
    ALLOW(ctx, waitid);
    ALLOW(ctx, getpid);
    ALLOW(ctx, getppid);
    ALLOW(ctx, gettid);
    ALLOW(ctx, getuid);
    ALLOW(ctx, geteuid);
    ALLOW(ctx, getgid);
    ALLOW(ctx, getegid);
    ALLOW(ctx, getgroups);
    ALLOW(ctx, getpgrp);
    ALLOW(ctx, getpgid);
    ALLOW(ctx, getsid);
    ALLOW(ctx, setpgid);
    ALLOW(ctx, setsid);
    /*
     * Read-only credential syscalls: kept because bash calls getresuid/getresgid
     * at startup (confirmed by kernel audit: syscall=118 triggered SIGSYS).
     * Write-side variants (setresuid, setresgid, setuid, setgid, setreuid,
     * setregid, capset) are intentionally removed per changes.md Part 1.3.
     */
    ALLOW(ctx, getresuid);
    ALLOW(ctx, getresgid);
    ALLOW(ctx, uname);
    ALLOW(ctx, prctl);
    ALLOW(ctx, setrlimit);
    ALLOW(ctx, getrlimit);
    ALLOW(ctx, prlimit64);
    ALLOW(ctx, getrusage);
    ALLOW(ctx, sysinfo);
    ALLOW(ctx, times);
    ALLOW(ctx, sched_getaffinity);
    ALLOW(ctx, sched_setaffinity);
    ALLOW(ctx, sched_yield);

    /* File descriptors */
    ALLOW(ctx, dup);
    ALLOW(ctx, dup2);
    ALLOW(ctx, dup3);
    ALLOW(ctx, pipe);
    ALLOW(ctx, pipe2);

    /* Signals */
    ALLOW(ctx, rt_sigaction);
    ALLOW(ctx, rt_sigprocmask);
    ALLOW(ctx, rt_sigreturn);
    ALLOW(ctx, rt_sigpending);
    ALLOW(ctx, rt_sigsuspend);
    ALLOW(ctx, sigaltstack);
    ALLOW(ctx, kill);
    ALLOW(ctx, tgkill);
    ALLOW(ctx, tkill);

    /* Time */
    ALLOW(ctx, nanosleep);
    ALLOW(ctx, clock_nanosleep);
    ALLOW(ctx, clock_gettime);
    ALLOW(ctx, clock_getres);
    ALLOW(ctx, gettimeofday);
    ALLOW(ctx, time);
    ALLOW(ctx, alarm);
    ALLOW(ctx, timer_create);
    ALLOW(ctx, timer_settime);
    ALLOW(ctx, timer_gettime);
    ALLOW(ctx, timer_delete);
    ALLOW(ctx, timerfd_create);
    ALLOW(ctx, timerfd_settime);
    ALLOW(ctx, timerfd_gettime);

    /* Polling / event I/O */
    ALLOW(ctx, poll);
    ALLOW(ctx, ppoll);
    ALLOW(ctx, select);
    ALLOW(ctx, pselect6);
    ALLOW(ctx, epoll_create);
    ALLOW(ctx, epoll_create1);
    ALLOW(ctx, epoll_ctl);
    ALLOW(ctx, epoll_wait);
    ALLOW(ctx, epoll_pwait);

    /* Thread primitives */
    ALLOW(ctx, futex);
    ALLOW(ctx, set_tid_address);
    ALLOW(ctx, set_robust_list);
    ALLOW(ctx, get_robust_list);
    ALLOW(ctx, arch_prctl);
    ALLOW(ctx, rseq);
    ALLOW(ctx, getrandom);

    /*
     * Unix-domain sockets ONLY (AF_UNIX == 1).
     * AF_INET, AF_INET6, AF_NETLINK, AF_PACKET are explicitly blocked.
     * The network namespace already prevents external connectivity, but
     * this provides defense-in-depth at the syscall level.
     */
    if (allow_unix_socket_only(ctx) != 0) return -1;
    ALLOW(ctx, connect);
    ALLOW(ctx, accept);
    ALLOW(ctx, accept4);
    ALLOW(ctx, bind);
    ALLOW(ctx, listen);
    ALLOW(ctx, getsockname);
    ALLOW(ctx, getpeername);
    ALLOW(ctx, setsockopt);
    ALLOW(ctx, getsockopt);
    ALLOW(ctx, sendto);
    ALLOW(ctx, recvfrom);
    ALLOW(ctx, sendmsg);
    ALLOW(ctx, recvmsg);
    ALLOW(ctx, shutdown);
    ALLOW(ctx, socketpair);

    /* Misc needed by bash/python startup */
    ALLOW(ctx, personality);
    ALLOW(ctx, sched_getattr);
    ALLOW(ctx, capget);
    /* capset intentionally removed — Part 1.3 */

    /* Required by modern glibc (2.35+) and bash (5.1+) */
    ALLOW(ctx, membarrier);
    ALLOW(ctx, close_range);
    ALLOW(ctx, openat2);
    ALLOW(ctx, setgroups);
    ALLOW(ctx, getpriority);
    ALLOW(ctx, setpriority);

    printf("[seccomp] Mode: STANDARD\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Mode: PERMISSIVE                                                  */
/*                                                                    */
/*  Everything in STANDARD plus extras needed for Python scripts      */
/*  and more complex interpreted programs.  Still blocks ptrace,      */
/*  mount, reboot, kexec, bpf, init_module.                          */
/* ------------------------------------------------------------------ */

static int install_permissive(scmp_filter_ctx ctx)
{
    /* Start with the standard set */
    if (install_standard(ctx) != 0) return -1;

    /* Extra syscalls needed by Python / dynamic loading */
    ALLOW(ctx, inotify_init1);
    ALLOW(ctx, inotify_add_watch);
    ALLOW(ctx, inotify_rm_watch);
    ALLOW(ctx, signalfd4);
    ALLOW(ctx, eventfd2);
    ALLOW(ctx, getrandom);
    /* read-only: lets ls -l list xattrs */
    ALLOW(ctx, listxattr);
    ALLOW(ctx, llistxattr);
    ALLOW(ctx, flistxattr);
    ALLOW(ctx, copy_file_range);
    ALLOW(ctx, sendfile);
    ALLOW(ctx, splice);
    ALLOW(ctx, tee);
    ALLOW(ctx, truncate);
    ALLOW(ctx, ftruncate);
    ALLOW(ctx, fallocate);
    ALLOW(ctx, sync);
    ALLOW(ctx, fsync);
    ALLOW(ctx, fdatasync);
    ALLOW(ctx, sync_file_range);
    ALLOW(ctx, rename);
    ALLOW(ctx, renameat);
    ALLOW(ctx, renameat2);
    ALLOW(ctx, link);
    ALLOW(ctx, linkat);
    ALLOW(ctx, symlink);
    ALLOW(ctx, symlinkat);
    ALLOW(ctx, unlink);
    ALLOW(ctx, unlinkat);
    ALLOW(ctx, mkdir);
    ALLOW(ctx, mkdirat);
    ALLOW(ctx, rmdir);
    ALLOW(ctx, chmod);
    ALLOW(ctx, fchmod);
    ALLOW(ctx, fchmodat);
    ALLOW(ctx, chown);
    ALLOW(ctx, fchown);
    ALLOW(ctx, lchown);
    ALLOW(ctx, fchownat);
    /*
     * Credential write syscalls (setuid/setgid/setresuid etc.) and
     * mknod/mknodat are intentionally excluded per changes.md Part 1.3.
     * getresuid/getresgid are already in STANDARD.
     */
    ALLOW(ctx, setgroups);
    ALLOW(ctx, rseq);
    ALLOW(ctx, time);

    printf("[seccomp] Mode: PERMISSIVE (extended syscall set)\n");
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

int seccomp_install_policy(seccomp_mode_t mode)
{
    /*
     * PR_SET_NO_NEW_PRIVS — prevents the sandboxed process from gaining
     * new privileges via setuid/setcap executables even if it tries to
     * exec one.  Required before seccomp_load() so that unprivileged
     * processes can apply a seccomp filter.
     */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("[seccomp] prctl PR_SET_NO_NEW_PRIVS");
        return -1;
    }

    /*
     * Default action:
     *   DEBUG builds  : SCMP_ACT_TRAP  — sends SIGSYS with si_errno info;
     *                   blocked syscalls are visible in strace/gdb for testing.
     *   Release builds: SCMP_ACT_KILL_PROCESS — kills the entire process group
     *                   on any syscall not in the allow-list (kernel 4.14+).
     */
#ifdef DEBUG
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_TRAP);
    fprintf(stderr, "[seccomp] DEBUG build: default action = SCMP_ACT_TRAP\n");
#else
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
#endif

    if (!ctx) {
        fprintf(stderr, "[seccomp] seccomp_init() failed\n");
        return -1;
    }

    int rc = 0;
    switch (mode) {
    case SECCOMP_MODE_MINIMAL:
        rc = install_minimal(ctx);
        break;
    case SECCOMP_MODE_STANDARD:
        rc = install_standard(ctx);
        break;
    case SECCOMP_MODE_PERMISSIVE:
        rc = install_permissive(ctx);
        break;
    default:
        fprintf(stderr, "[seccomp] Unknown mode %d\n", mode);
        rc = -1;
    }

    if (rc != 0) {
        seccomp_release(ctx);
        return -1;
    }

    /* Compile the BPF and install it into the kernel */
    rc = seccomp_load(ctx);
    if (rc != 0) {
        fprintf(stderr, "[seccomp] seccomp_load() failed: %s\n", strerror(-rc));
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);
    printf("[seccomp] Filter loaded successfully.\n");
    return 0;
}

seccomp_mode_t seccomp_mode_from_name(const char *name)
{
    if (!name) return SECCOMP_MODE_STANDARD;
    if (strcmp(name, "minimal")    == 0) return SECCOMP_MODE_MINIMAL;
    if (strcmp(name, "standard")   == 0) return SECCOMP_MODE_STANDARD;
    if (strcmp(name, "permissive") == 0) return SECCOMP_MODE_PERMISSIVE;

    fprintf(stderr, "[seccomp] Unknown mode '%s' — using standard\n", name);
    return SECCOMP_MODE_STANDARD;
}
