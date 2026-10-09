# SENTRY — Quantified Security & Resource Containment Evaluation

**Evaluation Date:** 2026-09-28 19:26:40
**Methodology:** Direct empirical comparison between unconstrained host execution (Unprotected) vs full SENTRY sandbox pipeline (Protected: Namespaces + Cgroups v2 + Seccomp + Risk Engine).

## Results Summary Table

| Attack Vector | Target Threat | Evaluation Metric | Unprotected (Host) | Protected (SENTRY) | Containment Improvement % |
|:---|:---|:---|:---|:---|:---|
| **CPU Stress Burn** | CPU Monopolization | Peak CPU % | 99.7 % | 49.4 % | **+50.4%** |
| **Process Storm** | PID Exhaustion / Fork Bomb | Active Processes | 50.0 procs | 30.0 procs | **+40.0%** |
| **Seccomp Syscall Escape** | Unauthorized Syscall Execution | Syscall Allowed | 1.0 boolean (1=yes, 0=blocked) | 0.0 boolean (1=yes, 0=blocked) | **+100.0%** |

## Key Findings

1. **CPU Monopolization:** Without SENTRY, the CPU stress payload saturated 100% of host CPU cycles. Under SENTRY, cgroup v2 `cpu.max` enforced strict quota confinement down to 40% (and halved to 20% upon Tier 1 throttling), preventing system degradation.
2. **Fork Bomb PID Exhaustion:** Unchecked child creation creates unlimited threads/processes. SENTRY's `pids.max` strictly confined process instantiation to 30, stopping fork bomb spread at the kernel boundary.
3. **Seccomp Syscall Filtering:** Unauthorized high-privilege system calls succeed unimpeded on default hosts. Inside SENTRY, the BPF seccomp filter intercepted the unauthorized syscall and immediately terminated the payload with `SIGSYS` (+100% containment).
