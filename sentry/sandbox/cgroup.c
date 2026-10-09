/*
 * cgroup.c — Phase 2: cgroups v2 resource control implementation
 *
 * Changes (Part 1.4 — Fix cgroup race and multi-run collision):
 *   - Each sandbox run gets a unique cgroup name: sentry_<child_pid>
 *   - Controllers (+cpu +memory +pids) are enabled in parent cgroup before mkdir
 *   - All write return values are logged
 *   - cgroup_add_pid is now called from inside the child via pipe handshake
 *     (the pipe coordination lives in sentry_sandbox_v3.c)
 *   - cgroup_destroy deletes the cgroup directory after child exits
 *
 * Requires: Linux kernel >= 5.x, cgroups v2 at /sys/fs/cgroup
 *           Run as root (CAP_SYS_ADMIN)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/mount.h>
#include <fcntl.h>

#include "cgroup.h"

/* ------------------------------------------------------------------ */
/*  Built-in profiles (Step 2.4)                                      */
/* ------------------------------------------------------------------ */

const sandbox_profile_t PROFILE_STRICT = {
    .name          = "strict",
    .cpu_percent   = 10,       /* 10% of one core     */
    .cpu_period_us = 100000,   /* 100 ms period        */
    .ram_mb        = 256,      /* 256 MB               */
    .max_pids      = 10,       /* 10 PIDs max          */
};

const sandbox_profile_t PROFILE_NORMAL = {
    .name          = "normal",
    .cpu_percent   = 40,       /* 40% of one core     */
    .cpu_period_us = 100000,
    .ram_mb        = 1024,     /* 1 GB                */
    .max_pids      = 30,
};

const sandbox_profile_t PROFILE_DEVELOPMENT = {
    .name          = "development",
    .cpu_percent   = 70,       /* 70% of one core     */
    .cpu_period_us = 100000,
    .ram_mb        = 2048,     /* 2 GB                */
    .max_pids      = 50,
};

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                  */
/* ------------------------------------------------------------------ */

/*
 * write_cgroup_file — Write a string to a cgroup control file.
 * Returns 0 on success, -1 on error (with errno set and error printed).
 */
static int write_cgroup_file(const char *path, const char *value)
{
    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd < 0) {
        fprintf(stderr, "[cgroup] Cannot open %s: %s\n", path, strerror(errno));
        return -1;
    }

    ssize_t written = write(fd, value, strlen(value));
    int saved_errno = errno;
    int rc = close(fd);
    if (rc != 0) {
        fprintf(stderr, "[cgroup] Warning: close(%s) failed: %s\n", path, strerror(errno));
    }

    if (written < 0) {
        errno = saved_errno;
        fprintf(stderr, "[cgroup] Cannot write '%s' to %s: %s\n",
                value, path, strerror(errno));
        return -1;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

/*
 * cgroup_build_path — Build a unique per-run cgroup path.
 * Format: /sys/fs/cgroup/sentry_<pid>
 */
void cgroup_build_path(char *buf, pid_t pid)
{
    snprintf(buf, SENTRY_CGROUP_PATH_MAX, "%s/sentry_%d", CGROUP_MOUNT, (int)pid);
}

/*
 * cgroup_verify_v2 — Confirm cgroups v2 is active.
 *
 * cgroup v2 uses the "cgroup2" filesystem type (magic 0x63677270).
 * We check via statfs() instead of parsing /proc/mounts to avoid
 * any potential race conditions or parsing issues.
 */
int cgroup_verify_v2(void)
{
    struct statfs st;
    if (statfs(CGROUP_MOUNT, &st) != 0) {
        perror("[cgroup] statfs(" CGROUP_MOUNT ")");
        return -1;
    }

    /* cgroup2 magic number */
    if ((unsigned long)st.f_type != 0x63677270UL) {
        fprintf(stderr,
            "[cgroup] ERROR: %s is not a cgroup v2 filesystem.\n"
            "         Check that cgroups v2 is enabled:\n"
            "           mount | grep cgroup2\n"
            "         or add 'cgroup_no_v1=all' to kernel cmdline.\n",
            CGROUP_MOUNT);
        return -1;
    }

    return 0;
}

/*
 * cgroup_create — Create a unique sentry_<pid> cgroup directory.
 *
 * Before creating the cgroup, enable the cpu, memory, and pids
 * controllers in the parent cgroup's subtree_control so the child
 * cgroup can actually use them.
 *
 * @param cgroup_path  Path built by cgroup_build_path().
 */
int cgroup_create(const char *cgroup_path)
{
    if (cgroup_verify_v2() != 0) {
        return -1;
    }

    /* Step 1.4 fix: Enable controllers in the parent cgroup first.
     * Writing to /sys/fs/cgroup/cgroup.subtree_control enables
     * cpu, memory, and pids controllers so child cgroups can use them. */
    const char *subtree_ctrl = CGROUP_MOUNT "/cgroup.subtree_control";
    if (write_cgroup_file(subtree_ctrl, "+cpu +memory +pids") != 0) {
        /* Non-fatal: may already be enabled, or may fail on some kernels */
        fprintf(stderr, "[cgroup] Warning: could not enable subtree controllers (may already be active)\n");
    } else {
        fprintf(stderr, "[cgroup] Enabled +cpu +memory +pids in subtree_control\n");
    }

    if (mkdir(cgroup_path, 0755) != 0 && errno != EEXIST) {
        fprintf(stderr, "[cgroup] Cannot create %s: %s\n",
                cgroup_path, strerror(errno));
        return -1;
    }

    printf("[cgroup] Created cgroup: %s\n", cgroup_path);
    return 0;
}

/*
 * cgroup_apply_profile — Write CPU/memory/PID limits.
 *
 * CPU limit (Step 2.1):
 *   cpu.max format: "<quota> <period>"
 *   quota = period * (cpu_percent / 100)
 *
 * Memory limit (Step 2.2):
 *   memory.max format: bytes as a decimal string
 *
 * PID limit (Step 2.3):
 *   pids.max format: decimal number or "max"
 *
 * @param cgroup_path  Path of the cgroup directory.
 * @param p            Profile to apply.
 */
int cgroup_apply_profile(const char *cgroup_path, const sandbox_profile_t *p)
{
    if (!p) {
        fprintf(stderr, "[cgroup] NULL profile\n");
        return -1;
    }

    char path[SENTRY_CGROUP_PATH_MAX + 32];
    char buf[256];

    /* --- Step 2.1: CPU limit --- */
    {
        /*
         * quota = period_us * cpu_percent / 100
         * e.g. 30% of a 100ms period = 30000 us
         */
        unsigned quota = p->cpu_period_us * p->cpu_percent / 100;
        snprintf(buf, sizeof(buf), "%u %u", quota, p->cpu_period_us);

        snprintf(path, sizeof(path), "%s/cpu.max", cgroup_path);
        printf("[cgroup] Setting CPU limit: %s (cpu.max)\n", buf);
        if (write_cgroup_file(path, buf) != 0) {
            return -1;
        }
    }

    /* --- Step 2.2: Memory limit --- */
    if (p->ram_mb > 0) {
        unsigned long ram_bytes = (unsigned long)p->ram_mb * 1024 * 1024;
        snprintf(buf, sizeof(buf), "%lu", ram_bytes);

        snprintf(path, sizeof(path), "%s/memory.max", cgroup_path);
        printf("[cgroup] Setting memory limit: %u MB (%s bytes)\n",
               p->ram_mb, buf);

        if (write_cgroup_file(path, buf) != 0) {
            return -1;
        }

        /* Also set swap to 0 (prevents swap from extending RAM) */
        snprintf(path, sizeof(path), "%s/memory.swap.max", cgroup_path);
        if (write_cgroup_file(path, "0") != 0) {
            /* non-fatal — may not be available on all kernels */
            fprintf(stderr, "[cgroup] Warning: could not set memory.swap.max\n");
        }
    }

    /* --- Step 2.3: PID limit --- */
    if (p->max_pids > 0) {
        snprintf(buf, sizeof(buf), "%u", p->max_pids);
        snprintf(path, sizeof(path), "%s/pids.max", cgroup_path);

        printf("[cgroup] Setting PID limit: %u (pids.max)\n", p->max_pids);
        if (write_cgroup_file(path, buf) != 0) {
            return -1;
        }
    }

    printf("[cgroup] Profile '%s' applied successfully.\n", p->name);
    return 0;
}

/*
 * cgroup_add_pid — Move a PID into the cgroup.
 *
 * Writing the PID to cgroup.procs atomically migrates the process
 * (and all its threads) into the cgroup.
 *
 * @param cgroup_path  Path of the cgroup directory.
 * @param pid          PID to move.
 */
int cgroup_add_pid(const char *cgroup_path, pid_t pid)
{
    char path[SENTRY_CGROUP_PATH_MAX + 32];
    char buf[32];

    snprintf(path, sizeof(path), "%s/cgroup.procs", cgroup_path);
    snprintf(buf, sizeof(buf), "%d", (int)pid);

    printf("[cgroup] Adding PID %d to cgroup %s\n", (int)pid, cgroup_path);
    if (write_cgroup_file(path, buf) != 0) {
        fprintf(stderr, "[cgroup] ERROR: Failed to add PID %d to cgroup\n", (int)pid);
        return -1;
    }

    return 0;
}

/*
 * cgroup_destroy — Remove the sentry_<pid> cgroup.
 *
 * The kernel only allows rmdir() on a cgroup when it has no processes
 * in it.  This should be safe to call after waitpid() returns.
 *
 * @param cgroup_path  Path of the cgroup directory.
 */
int cgroup_destroy(const char *cgroup_path)
{
    if (rmdir(cgroup_path) != 0) {
        /* ENOENT is fine — already gone */
        if (errno != ENOENT) {
            fprintf(stderr, "[cgroup] Cannot remove %s: %s\n",
                    cgroup_path, strerror(errno));
            return -1;
        }
    }

    printf("[cgroup] Cgroup %s removed.\n", cgroup_path);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Profile lookup (Step 2.4)                                         */
/* ------------------------------------------------------------------ */

const sandbox_profile_t *profile_from_name(const char *name)
{
    if (!name) return NULL;

    if (strcmp(name, "strict")      == 0) return &PROFILE_STRICT;
    if (strcmp(name, "normal")      == 0) return &PROFILE_NORMAL;
    if (strcmp(name, "development") == 0) return &PROFILE_DEVELOPMENT;

    fprintf(stderr, "[cgroup] Unknown profile '%s'. "
            "Use: strict | normal | development\n", name);
    return NULL;
}
