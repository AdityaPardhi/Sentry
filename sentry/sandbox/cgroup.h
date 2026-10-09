/*
 * cgroup.h — Step 2: cgroups v2 helper interface
 *
 * Provides functions to create a named cgroup under /sys/fs/cgroup/sentry/,
 * apply CPU / memory / PID limits, add a process to the cgroup, and clean up.
 *
 * Requires: Linux kernel >= 5.x with cgroups v2 mounted at /sys/fs/cgroup
 *           Run as root (CAP_SYS_ADMIN).
 *
 * Change (Part 1.4): cgroup names are now unique per run using the child PID:
 *   sentry_<pid>  e.g. /sys/fs/cgroup/sentry_12345
 *
 * The SENTRY_CGROUP macro is kept for legacy but the live path is built by
 * cgroup_path_for_pid() and stored in the returned char buffer.
 */

#ifndef CGROUP_H
#define CGROUP_H

#include <sys/types.h>

/* Root of the cgroup v2 hierarchy */
#define CGROUP_MOUNT    "/sys/fs/cgroup"

/* Maximum length of a per-run cgroup path */
#define SENTRY_CGROUP_PATH_MAX  128

/* ------------------------------------------------------------------ */
/*  Sandbox profile                                                   */
/* ------------------------------------------------------------------ */

/*
 * sandbox_profile — named resource cap configuration.
 *
 * cpu_percent : percentage of a single CPU core (1–100)
 * cpu_period_us: scheduling period in microseconds (default 100000 = 100ms)
 * ram_mb      : maximum RSS in megabytes (0 = no limit)
 * max_pids    : maximum number of PIDs in the cgroup (0 = no limit)
 */
typedef struct sandbox_profile {
    const char *name;
    int         cpu_percent;    /* e.g. 30 for 30% */
    unsigned    cpu_period_us;  /* e.g. 100000      */
    unsigned    ram_mb;         /* e.g. 512         */
    unsigned    max_pids;       /* e.g. 20          */
} sandbox_profile_t;

/* Built-in profiles (from plan step 2.4) */
extern const sandbox_profile_t PROFILE_STRICT;
extern const sandbox_profile_t PROFILE_NORMAL;
extern const sandbox_profile_t PROFILE_DEVELOPMENT;

/* ------------------------------------------------------------------ */
/*  API                                                               */
/* ------------------------------------------------------------------ */

/**
 * cgroup_build_path — Build a unique per-run cgroup path into buf.
 *
 * @param buf    Buffer of at least SENTRY_CGROUP_PATH_MAX bytes.
 * @param pid    Child PID to embed in the name.
 */
void cgroup_build_path(char *buf, pid_t pid);

/**
 * cgroup_create — Create a unique sentry_<pid> cgroup.
 * Enables cpu, memory, and pids controllers in the parent cgroup first.
 * Must be called before the child process is started.
 *
 * @param cgroup_path  Output buffer filled by cgroup_build_path().
 * @return  0 on success, -1 on error
 */
int cgroup_create(const char *cgroup_path);

/**
 * cgroup_apply_profile — Write CPU/memory/PID limits from a profile.
 *
 * @param cgroup_path  Path of the cgroup directory.
 * @param p            Profile to apply.
 * @return   0 on success, -1 on error
 */
int cgroup_apply_profile(const char *cgroup_path, const sandbox_profile_t *p);

/**
 * cgroup_add_pid — Move a process into the cgroup.
 *
 * @param cgroup_path  Path of the cgroup directory.
 * @param pid          PID to move.
 * @return     0 on success, -1 on error
 */
int cgroup_add_pid(const char *cgroup_path, pid_t pid);

/**
 * cgroup_destroy — Remove the sentry_<pid> cgroup directory.
 * Call after the sandboxed process has exited.
 *
 * @param cgroup_path  Path of the cgroup directory.
 * @return  0 on success, -1 on error
 */
int cgroup_destroy(const char *cgroup_path);

/**
 * cgroup_verify_v2 — Confirm cgroups v2 is mounted at CGROUP_MOUNT.
 *
 * @return  0 if v2 is available, -1 otherwise
 */
int cgroup_verify_v2(void);

/**
 * profile_from_name — Look up a built-in profile by name.
 *
 * @param name  "strict" | "normal" | "development"
 * @return      pointer to profile, or NULL if not found
 */
const sandbox_profile_t *profile_from_name(const char *name);

#endif /* CGROUP_H */
