/*
 * seccomp_policy.h — Phase 3: seccomp syscall allow-list interface
 *
 * Provides functions to install a seccomp BPF filter (via libseccomp)
 * that restricts which syscalls a sandboxed process may invoke.
 *
 * Steps implemented:
 *   3.1  Basic allow-list using libseccomp
 *   3.2  Test that a blocked syscall kills the process (SIGSYS)
 *   3.3  Tuned policy so ordinary programs (ls, cat, echo) still work
 *
 * Must be called INSIDE the child process, AFTER chroot/namespace
 * setup and BEFORE execvp().
 *
 * Requires: libseccomp-dev
 *           sudo apt install libseccomp-dev
 * Link:     -lseccomp
 */

#ifndef SECCOMP_POLICY_H
#define SECCOMP_POLICY_H

/*
 * seccomp_mode — selects how restrictive the filter should be.
 *
 * SECCOMP_MODE_MINIMAL
 *   Absolute bare minimum — only allows syscalls needed by a static
 *   hello-world.  Good for testing that blocks actually fire.
 *
 * SECCOMP_MODE_STANDARD
 *   Enough to run common utilities: ls, cat, echo, grep, ps, find.
 *   Blocks ptrace, mount, reboot, kexec, and raw socket creation.
 *   This is the default for SENTRY.
 *
 * SECCOMP_MODE_PERMISSIVE
 *   A broader allow-list for interpreted languages (Python/bash scripts).
 *   Still blocks the most dangerous syscalls.
 */
typedef enum {
    SECCOMP_MODE_MINIMAL    = 0,
    SECCOMP_MODE_STANDARD   = 1,
    SECCOMP_MODE_PERMISSIVE = 2,
} seccomp_mode_t;

/**
 * seccomp_install_policy — Load the seccomp BPF filter into the calling
 * process (and all its future children via PR_SET_NO_NEW_PRIVS semantics).
 *
 * Default action: SCMP_ACT_KILL_PROCESS — any syscall not on the
 * allow-list immediately terminates the process with SIGSYS.
 *
 * @param mode  How restrictive the policy should be.
 * @return      0 on success, -1 on error.
 */
int seccomp_install_policy(seccomp_mode_t mode);

/**
 * seccomp_mode_from_name — Parse a mode string.
 *
 * @param name  "minimal" | "standard" | "permissive"
 * @return      Matching mode, or SECCOMP_MODE_STANDARD if not found.
 */
seccomp_mode_t seccomp_mode_from_name(const char *name);

#endif /* SECCOMP_POLICY_H */
