Sentry Sandbox — Security Hardening & Cleanup

You are working on the Sentry project. Its sole agenda is: run arbitrary Linux executables in a secure sandbox that has zero effect on the real host system — no real files, no real processes, no real network interfaces are touched. Fix every issue below to fully achieve this agenda.

PART 1 — CRITICAL SECURITY FIXES (do all of these)

1. Add a user namespace + drop all capabilities
In sentry_sandbox_v3.c, add CLONE_NEWUSER to the clone() flags. Before execve, write the UID/GID maps (/proc/self/uid_map, gid_map) so the sandboxed process thinks it is UID 0 inside but maps to a real unprivileged UID (e.g. 65534) on the host. After chroot, call prctl(PR_SET_KEEPCAPS, 0) and then capset() to drop every capability in the effective, permitted, and inheritable sets. The sandboxed program must have no capabilities from the host's perspective.

2. Replace chroot with pivot_root + read-only base + tmpfs scratch layer
Remove the chroot() call. Instead:

Mount the existing sandbox root directory as read-only with MS_BIND | MS_RDONLY | MS_REMOUNT.
Mount a tmpfs on top of it for the scratch layer (use overlayfs if available, tmpfs otherwise) so writes are thrown away at process exit.
Call pivot_root() to make this the actual root.
Unmount the old root and remove it.
Also mount a minimal /dev (only null, zero, urandom) and make /proc read-only with MS_RDONLY after mounting.
Mask dangerous proc paths: bind-mount /dev/null over /proc/sysrq-trigger, /proc/sys/kernel/core_pattern, and /proc/kcore before exec.

3. Tighten the seccomp policy in seccomp_policy.c
Make these specific changes:

Change socket() to only allow AF_UNIX (domain == 1). Block AF_INET, AF_INET6, AF_NETLINK.
Remove setuid, setgid, setreuid, setregid, setresuid, setresgid, capset from the allow-list.
Remove mknod and mknodat from the allow-list.
On clone/clone3, add a flag argument check that blocks CLONE_NEWUSER (0x10000000) — use SCMP_CMP_MASKED_EQ.
Remove memfd_create from the allow-list.
Change the default action from SCMP_ACT_KILL to SCMP_ACT_TRAP in debug builds (#ifdef DEBUG), so blocked syscalls are visible during testing, and keep SCMP_ACT_KILL_PROCESS in release builds.

4. Fix the cgroup race and multi-run collision in cgroup.c

Generate a unique cgroup name per run using the child PID: e.g. sentry_<pid>.
Before calling cgroup_add_pid, enable the controllers: write +cpu +memory +pids to cgroup.subtree_control in the parent cgroup.
Check and log the return value of every cgroup write.
Move the cgroup_add_pid call to happen before execve inside the child (use a pipe as a handshake: child waits on pipe read, parent writes after adding PID to cgroup, child then continues to exec).
In cgroup_cleanup, delete the cgroup directory after the child exits.

5. Fix the control channel — stop trusting sandbox stdout
In cli/sentry.py, stop regex-parsing the sandboxed program's stdout for "child PID = N" and "SIGSYS". Instead:

Pass a separate socketpair or pipe fd to the C sandbox binary (add a --control-fd N argument).
The C binary writes a single line PID:<child_pid>\n to that fd before exec, then closes it.
The CLI reads from its end of the pair to get the real PID. Never trust anything from the program's stdout for security decisions.
In response_engine.py, only call os.kill(pid, SIGKILL) on a PID obtained from this trusted control channel.

PART 2 — CLEANUP (remove these, they are off-agenda)

Delete or remove the following from the repo:

monitor/ml_anomaly.py and every import of it — ML anomaly detection is out of scope.
The web dashboard and CSV export code in the CLI — out of scope.
Old sandbox binaries: sandbox/sentry_sandbox.c, sandbox/sentry_sandbox_v2.c, sandbox/sandbox_pid.c, sandbox/sandbox_mount.c, sandbox/sandbox_net.c.
sandbox/seccomp_policy.c.bak.
The empty risk/ and response/ packages (the code is in monitor/, these are confusing dead weight).
The committed sentry.db file and any __pycache__ directories.
Prebuilt binaries in bin/ — they should be built by make, not committed.
The escalation state machine in response_engine.py — replace the whole thing with: throttle 3 violations → SIGKILL → cgroup freeze → log. Nothing more.

PART 3 — ADD ESCAPE TEST SUITE

Create tests/escape_tests.sh. It should:

Record SHA-256 hashes of a set of host files (e.g. /etc/passwd, /tmp/sentry_host_marker_<random>) before running the sandbox.
Run the sandbox with each of the following test programs (create minimal C source files for each in tests/escape_src/):
read_host_file.c — tries to open /etc/passwd via ../../../etc/passwd
write_proc.c — tries to write to /proc/sysrq-trigger
mknod_dev.c — tries mknod("/tmp/sda", S_IFBLK, makedev(8,0))
chroot_escape.c — classic chroot escape (mkdir + chroot loop)
fork_bomb.c — forks until limit
raw_socket.c — tries socket(AF_INET, SOCK_RAW, 0)
After each run, verify the host files are unchanged (compare hashes).
Print PASS/FAIL per test. All should PASS (i.e. the escape was blocked).
Add a make test target in Makefile that runs this script.

PART 4 — SMALL CORRECTNESS FIXES

In sandbox/sentry_sandbox_v3.c: add CLONE_NEWUTS and CLONE_NEWIPC to the clone() flags. Mount a fresh tmpfs on /tmp inside the sandbox before exec.
In cli/sentry.py: add a wall-clock timeout (default 30 s, configurable via --timeout) using signal.alarm or threading.Timer that sends SIGKILL to the sandbox PID and then cleans up the cgroup.
In monitor/network_monitor.py: since the sandbox has no real network interface, update the monitor to watch only for AF_UNIX socket activity inside the sandbox's network namespace (via /proc/<pid>/net/unix), and remove the TCP/UDP polling which always sees host traffic.
Add CLONE_NEWNS to mount namespace flags if not already set explicitly.

Acceptance criteria (check these after all changes):

make builds cleanly with no warnings on -Wall -Wextra.
make test runs all escape tests and all print PASS.
Running the sandbox with a benign program (e.g. /bin/ls) produces output and exits cleanly.
No host file is modified by any sandboxed run. No capabilities are available to the sandboxed process (verify with capsh --print inside the sandbox or check /proc/<pid>/status CapEff).
The cgroup is created per-run with a unique name and deleted after exit.
