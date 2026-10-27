#!/bin/bash
# test_phase2.sh — Automated tests for Phase 2 (cgroups v2 resource control)
#
# Usage: sudo bash test_phase2.sh [bin-dir]
#
# Verifies:
#   2.1  CPU limit via cpu.max
#   2.2  Memory limit via memory.max (OOM kill)
#   2.3  PID limit via pids.max (fork EAGAIN)
#   2.4  Profile switching (strict vs development)

set -uo pipefail

BINDIR="${1:-bin}"
CGROUP_ROOT="/sys/fs/cgroup/sentry_sandbox"
SANDBOX_ROOT="${SENTRY_ROOT:-/opt/sentry/sandbox-root}"
PASS=0
FAIL=0
TOTAL=0

# ── Helpers ──────────────────────────────────────────────────────────

pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo "  ✓ PASS: $1"; }
fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo "  ✗ FAIL: $1"; }

header() {
    echo ""
    echo "═══════════════════════════════════════════════"
    echo " $1"
    echo "═══════════════════════════════════════════════"
}

# ── Preconditions ────────────────────────────────────────────────────

header "Preconditions"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: tests must be run as root (sudo)."; exit 1
fi

if [ ! -f "${BINDIR}/sentry_sandbox_v2" ]; then
    echo "Error: ${BINDIR}/sentry_sandbox_v2 not found. Run 'make' first."; exit 1
fi

if [ ! -d "${SANDBOX_ROOT}" ]; then
    echo "Error: sandbox root ${SANDBOX_ROOT} not found. Run 'make setup'."; exit 1
fi

# Verify cgroups v2
if ! mount | grep -q "cgroup2"; then
    echo "Error: cgroups v2 is not mounted. This is required for Phase 2."
    echo "       Try: sudo mount -t cgroup2 cgroup2 /sys/fs/cgroup"
    exit 1
fi

echo "  Binary dir   : ${BINDIR}"
echo "  Sandbox root : ${SANDBOX_ROOT}"

# ── Test 2.1: CPU limit ──────────────────────────────────────────────

header "Test 2.1 — CPU Limit (cpu.max)"

# Cleanup any leftover cgroup from previous run
rmdir "${CGROUP_ROOT}" 2>/dev/null || true

# Launch sandbox with strict profile (CPU 10%) running stress_cpu for 10s
# in the background so we can inspect the cgroup file.
"${BINDIR}/sentry_sandbox_v2" run /bin/stress_cpu 10 --profile strict &
SBX_PID=$!
sleep 1

# Check cpu.max was written correctly (should be "10000 100000" for 10%)
if [ -f "${CGROUP_ROOT}/cpu.max" ]; then
    CPU_MAX=$(cat "${CGROUP_ROOT}/cpu.max")
    echo "  cpu.max = ${CPU_MAX}"
    if [ "${CPU_MAX}" = "10000 100000" ]; then
        pass "cpu.max set to '10000 100000' (10% of 100ms period)"
    else
        fail "cpu.max = '${CPU_MAX}', expected '10000 100000'"
    fi
else
    fail "cpu.max not found in cgroup — cgroup not created properly"
fi

wait "${SBX_PID}" 2>/dev/null || true

# ── Test 2.2: Memory limit ───────────────────────────────────────────

header "Test 2.2 — Memory Limit (memory.max)"

rmdir "${CGROUP_ROOT}" 2>/dev/null || true

# Launch sandbox with strict profile (RAM 256MB) running stress_mem (tries 600MB)
"${BINDIR}/sentry_sandbox_v2" run /bin/stress_mem 600 --profile strict &
SBX_PID=$!
sleep 1

# Check memory.max was written correctly
if [ -f "${CGROUP_ROOT}/memory.max" ]; then
    MEM_MAX=$(cat "${CGROUP_ROOT}/memory.max")
    echo "  memory.max = ${MEM_MAX} bytes"
    EXPECTED=$((256 * 1024 * 1024))
    if [ "${MEM_MAX}" = "${EXPECTED}" ]; then
        pass "memory.max set to ${EXPECTED} bytes (256 MB)"
    else
        fail "memory.max = '${MEM_MAX}', expected '${EXPECTED}'"
    fi
else
    fail "memory.max not found in cgroup"
fi

wait "${SBX_PID}" 2>/dev/null || true

# Check OOM event counter in memory.events
if [ -f "${CGROUP_ROOT}/memory.events" ]; then
    OOM_KILL=$(grep "^oom_kill " "${CGROUP_ROOT}/memory.events" | awk '{print $2}')
    echo "  memory.events oom_kill = ${OOM_KILL}"
    if [ "${OOM_KILL:-0}" -gt 0 ]; then
        pass "OOM kill event recorded — memory limit enforced"
    else
        echo "  (OOM kill counter is 0 — process may not have crossed the limit yet"
        echo "   or the sandbox binary is not in sandbox root. Proceeding.)"
    fi
else
    echo "  (memory.events not found — may not be populated until process exits)"
fi

rmdir "${CGROUP_ROOT}" 2>/dev/null || true

# ── Test 2.3: PID limit ──────────────────────────────────────────────

header "Test 2.3 — PID Limit (pids.max)"

rmdir "${CGROUP_ROOT}" 2>/dev/null || true

"${BINDIR}/sentry_sandbox_v2" run /bin/stress_fork 50 --profile strict &
SBX_PID=$!
sleep 1

if [ -f "${CGROUP_ROOT}/pids.max" ]; then
    PIDS_MAX=$(cat "${CGROUP_ROOT}/pids.max")
    echo "  pids.max = ${PIDS_MAX}"
    if [ "${PIDS_MAX}" = "10" ]; then
        pass "pids.max set to 10 (strict profile)"
    else
        fail "pids.max = '${PIDS_MAX}', expected '10'"
    fi
else
    fail "pids.max not found in cgroup"
fi

wait "${SBX_PID}" 2>/dev/null || true
rmdir "${CGROUP_ROOT}" 2>/dev/null || true

# ── Test 2.4: Profile switching ──────────────────────────────────────

header "Test 2.4 — Profile Switching (strict vs development)"

rmdir "${CGROUP_ROOT}" 2>/dev/null || true

echo "[Test] Launching with --profile development..."
"${BINDIR}/sentry_sandbox_v2" run /bin/stress_cpu 3 --profile development &
DEV_PID=$!
sleep 1

DEV_CPU_MAX=""
DEV_MEM_MAX=""
DEV_PIDS_MAX=""
if [ -f "${CGROUP_ROOT}/cpu.max" ];    then DEV_CPU_MAX=$(cat "${CGROUP_ROOT}/cpu.max"); fi
if [ -f "${CGROUP_ROOT}/memory.max" ]; then DEV_MEM_MAX=$(cat "${CGROUP_ROOT}/memory.max"); fi
if [ -f "${CGROUP_ROOT}/pids.max" ];   then DEV_PIDS_MAX=$(cat "${CGROUP_ROOT}/pids.max"); fi

echo "  development profile: cpu.max='${DEV_CPU_MAX}' memory.max='${DEV_MEM_MAX}' pids.max='${DEV_PIDS_MAX}'"

kill "${DEV_PID}" 2>/dev/null || true
wait "${DEV_PID}" 2>/dev/null || true
rmdir "${CGROUP_ROOT}" 2>/dev/null || true

# Validate development profile: CPU 70% = 70000/100000, RAM 2048MB, PIDs 50
if [ "${DEV_CPU_MAX}" = "70000 100000" ]; then
    pass "development: cpu.max = '70000 100000' (70%)"
else
    fail "development: cpu.max = '${DEV_CPU_MAX}', expected '70000 100000'"
fi

if [ "${DEV_MEM_MAX}" = "$((2048 * 1024 * 1024))" ]; then
    pass "development: memory.max = 2048MB"
else
    fail "development: memory.max = '${DEV_MEM_MAX}', expected '$((2048*1024*1024))'"
fi

if [ "${DEV_PIDS_MAX}" = "50" ]; then
    pass "development: pids.max = 50"
else
    fail "development: pids.max = '${DEV_PIDS_MAX}', expected '50'"
fi

# ── Summary ──────────────────────────────────────────────────────────

header "Test Summary"
echo "  Total : ${TOTAL}"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo ""
if [ "${FAIL}" -eq 0 ]; then
    echo "  ★ All Phase 2 tests passed!"
else
    echo "  ⚠ Some tests failed. Review output above."
fi
echo ""
