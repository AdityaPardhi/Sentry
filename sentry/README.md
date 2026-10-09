# SENTRY — Secure Linux Sandbox & Malware Behavior Monitor

A multi-layered Linux sandbox and behavior monitor designed to run arbitrary Linux
executables in a secure container with **zero effect on the real host system** —
no real files, no real processes, and no real network interfaces are touched.

---

## Architecture Overview

```
Untrusted Binary
       │
       ▼
┌────────────────────────────────────────────────────────────────────────┐
│  SENTRY Linux Sandbox (C / Kernel Primitives)                          │
│   ├── Namespaces: PID, Mount/Pivot-Root (read-only base + tmpfs),      │
│   │               Network (loopback only), UTS, IPC, User              │
│   ├── Cgroups v2: cpu.max quota, memory.max ceiling, pids.max cap      │
│   │               Unique per-run cgroup (sentry_<pid>); pipe handshake  │
│   └── Seccomp BPF: Minimal/Standard/Permissive syscall allow-lists;    │
│                    AF_UNIX-only sockets; CLONE_NEWUSER blocked;         │
│                    SCMP_ACT_KILL_PROCESS (release) / SCMP_ACT_TRAP (debug)│
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Trusted control channel (socketpair/pipe)
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Real-Time Behavior Monitors (Python)                                  │
│   ├── Process Monitor : /proc/<pid>/stat, status, child process tree   │
│   ├── File Monitor    : inotify watch, mass write burst rate (RPM)     │
│   └── Network Monitor : /proc/<pid>/net/unix — AF_UNIX socket activity │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Live Telemetry Samples
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Explainable Threat Engine                                             │
│   ├── Point-based heuristic rule attribution (0–100 score)             │
│   └── Threat Band Mapping: NORMAL / LOW / MEDIUM / HIGH / CRITICAL     │
└──────────────────────────────────┬─────────────────────────────────────┘
                                   │ Trigger Action
                                   ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Simplified Response & Forensics                                       │
│   ├── Throttle 3 violations → halve cgroup cpu.max                     │
│   ├── SIGKILL process                                                  │
│   ├── Cgroup freeze                                                    │
│   └── Log incident to SQLite (15-field schema)                         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Repository Layout

```
sentry/
├── sandbox/          # C sandbox: namespaces, cgroups v2, seccomp BPF filters
│   ├── sentry_sandbox_v3.c   # Main sandbox: pivot_root, user-ns, capability drop
│   ├── cgroup.c / cgroup.h   # Cgroups v2 resource control
│   ├── seccomp_policy.c / .h # Seccomp BPF syscall allow-lists
│   └── setup_sandbox_root.sh # Prepares /opt/sentry/sandbox-root
├── monitor/          # Behavior monitors: process, inotify file, AF_UNIX network
├── db/               # SQLite database manager and forensic incident reporting
├── tests/            # Escape test suite (Part 3) + stress test C sources
│   ├── escape_tests.sh       # Runs all 6 escape-attempt programs
│   └── escape_src/           # C sources: read_host_file, write_proc, mknod_dev,
│                             #             chroot_escape, fork_bomb, raw_socket
├── cli/              # Unified CLI: sentry run, monitor, report, status
└── bin/              # Compiled ELF binaries (built via make, not committed)
```

---

## Quick Start & Build Instructions

### Prerequisites
- Linux kernel ≥ 5.x (or Ubuntu on WSL2)
- GCC, Make, Python 3.8+
- `libseccomp-dev`, `libcap-dev`
  ```bash
  sudo apt install -y build-essential libseccomp-dev libcap-dev
  ```
- Root privileges (`sudo`) for namespace and cgroup operations

### Compilation & Sandbox Root Setup
```bash
cd sentry/
make setup            # Sets up minimal root filesystem at /opt/sentry/sandbox-root
make                  # Compiles sentry_sandbox_v3 and all test helpers
make install-tests    # Copies stress test binaries into sandbox root
```

### Run the Escape Test Suite
```bash
make test             # Builds escape binaries and runs tests/escape_tests.sh (requires sudo)
```

All 6 tests should print **PASS** — verifying the sandbox blocks every escape attempt.

---

## Security Properties

| Property | Mechanism |
|:---|:---|
| Filesystem isolation | `pivot_root` + read-only bind-mount + tmpfs scratch layer; old root unmounted |
| No host file access | `/etc/passwd`, `/proc/kcore`, `/proc/sysrq-trigger` masked with `/dev/null` |
| No capabilities | `CLONE_NEWUSER` + UID/GID map (host→0) + `capset` drops all effective caps |
| No network escape | Isolated network namespace (loopback only) + seccomp blocks non-AF_UNIX sockets |
| No fork bombs | `pids.max` via cgroups v2; unique per-run cgroup `sentry_<pid>` cleaned up after exit |
| No namespace escape | seccomp blocks `CLONE_NEWUSER` (0x10000000) via `SCMP_CMP_MASKED_EQ` |
| No privilege escalation | `PR_SET_NO_NEW_PRIVS` before seccomp load; `setuid`/`setgid`/`capset` removed from allow-list |
| Trusted PID channel | `--control-fd` pipe writes `PID:<n>\n` before exec; CLI never parses sandboxed stdout for security decisions |
| Unique per-run cgroup | `sentry_<child_pid>` created, limits applied, PID added (via pipe handshake), cleaned up after `waitpid` |

---

## User Commands & Execution Modes

### 1. Launch Program Inside Monitored Sandbox
```bash
sudo python3 -u cli/sentry.py run /bin/stress_files 150 /tmp \
    --profile normal \
    --seccomp standard \
    --db sentry.db \
    --interval 0.5 \
    --timeout 30
```

### 2. View Live ASCII Status Dashboard
```bash
# Print single snapshot
python3 cli/sentry.py status --once --db sentry.db

# Live auto-refreshing monitor
python3 cli/sentry.py status --interval 1.0 --db sentry.db
```

### 3. Forensic Incident & Telemetry Reports
```bash
# Telemetry summary
python3 cli/sentry.py report --db sentry.db

# Formatted digital forensics incident report card
python3 db/incidents_report.py --db sentry.db

# Table view
python3 db/incidents_report.py --db sentry.db --format table

# JSON output
python3 db/incidents_report.py --db sentry.db --format json
```

### 4. Run Full Attack Replay Test Suite
```bash
sudo python3 -u tests/run_all.py --db /tmp/sentry_attack_test.db
```

### 5. Run Quantified Protection Evaluation
```bash
sudo python3 -u tests/evaluate_comparison.py --output comparison_report.md
```

---

## Acceptance Criteria (changes.md)

- `make` builds cleanly with no warnings (`-Wall -Wextra`).
- `make test` runs all 6 escape tests and all print **PASS**.
- Running the sandbox with a benign program (e.g. `/bin/ls`) produces output and exits cleanly.
- No host file is modified by any sandboxed run.
- No capabilities are available to the sandboxed process (`CapEff == 0` in `/proc/<pid>/status`).
- The cgroup is created per-run with a unique name (`sentry_<pid>`) and deleted after exit.

---

## Seccomp Modes

| Mode | Description |
|:---|:---|
| `minimal` | Bare-minimum syscalls (static binaries / test programs) |
| `standard` | Common utilities: `ls`, `cat`, `echo`, `bash` (default) |
| `permissive` | Extended set for Python scripts and dynamic languages |

In all modes: non-AF_UNIX sockets blocked, `setuid`/`setgid`/`capset`/`mknod`/`memfd_create` removed, `CLONE_NEWUSER` blocked.

---

## Resource Profiles

| Profile | CPU | RAM | PIDs |
|:---|:---|:---|:---|
| `strict` | 10% | 256 MB | 10 |
| `normal` | 40% | 1 GB | 30 (default) |
| `development` | 70% | 2 GB | 50 |
