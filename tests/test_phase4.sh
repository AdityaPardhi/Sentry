#!/bin/bash
# test_phase4.sh — Automated tests for Phase 4 (Process Behavior Monitoring)
#
# Usage: sudo bash test_phase4.sh [bin-dir]
#
# Verifies:
#   4.1  CPU% calculation from /proc/<pid>/stat
#   4.2  Memory (VmRSS) extraction from /proc/<pid>/status
#   4.3  Child process tracking & spawn rate calculation
#   4.4  SQLite time-series logging into process_samples table
#   4.5  Integration: live monitoring of sandbox_v3 execution via CLI

set -uo pipefail

BINDIR="${1:-bin}"
SANDBOX_ROOT="${SENTRY_ROOT:-/opt/sentry/sandbox-root}"
PASS=0
FAIL=0
TOTAL=0

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

if [ "$(id -u)" -ne 0 ]; then echo "Error: run as root (sudo)."; exit 1; fi

if ! command -v python3 &>/dev/null; then
    echo "Error: python3 is required for Phase 4 monitoring."; exit 1
fi

if [ ! -f "${BINDIR}/sentry_sandbox_v3" ]; then
    echo "Error: ${BINDIR}/sentry_sandbox_v3 not found. Run 'make'."; exit 1
fi

echo "  Binary dir   : ${BINDIR}"
echo "  Sandbox root : ${SANDBOX_ROOT}"
echo "  Python       : $(python3 --version)"

# ── Test 4.1–4.4: Python ProcessMonitor Unit & Stress Verification ───

header "Test 4.1–4.4 — ProcessMonitor Metrics & SQLite Persistence"

TEST_DB="test_phase4_temp.db"
rm -f "${TEST_DB}"

python3 tests/test_process_monitor.py
if [ $? -eq 0 ]; then
    pass "ProcessMonitor correctly computes CPU%, VmRSS, child tree spawn rate, and logs to SQLite"
else
    fail "ProcessMonitor test suite failed"
fi

# ── Test 4.5: End-to-End Sandbox + Live Monitoring ──────────────────

header "Test 4.5 — End-to-End Sandbox Execution with Live Monitoring"

LIVE_DB="test_phase4_live.db"
rm -f "${LIVE_DB}"

# Ensure stress_cpu is inside sandbox root
if [ -d "${SANDBOX_ROOT}/bin" ] && [ -f "${BINDIR}/stress_cpu" ]; then
    cp -f "${BINDIR}/stress_cpu" "${SANDBOX_ROOT}/bin/stress_cpu"
    chmod 755 "${SANDBOX_ROOT}/bin/stress_cpu"
fi

# Run sentry CLI to launch stress_cpu in sandbox with live monitoring
echo "[*] Launching stress_cpu in sandbox via cli/sentry.py..."
python3 cli/sentry.py run /bin/stress_cpu 3 \
    --profile normal \
    --seccomp standard \
    --db "${LIVE_DB}" \
    --interval 0.5 > /tmp/sentry_live_test.log 2>&1

cat /tmp/sentry_live_test.log

# Verify that database exists and contains samples
if [ -f "${LIVE_DB}" ]; then
    pass "Telemetry database was created"
else
    fail "Telemetry database was not created"
fi

# Query DB for recorded samples
SAMPLE_COUNT=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${LIVE_DB}')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM process_samples;')
print(c.fetchone()[0])
")

echo "  Logged samples in ${LIVE_DB}: ${SAMPLE_COUNT}"

if [ "${SAMPLE_COUNT}" -ge 2 ]; then
    pass "Process telemetry recorded ${SAMPLE_COUNT} time-series samples"
else
    fail "Expected at least 2 samples, got ${SAMPLE_COUNT}"
fi

# Check peak CPU recorded
PEAK_CPU=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${LIVE_DB}')
c = conn.cursor()
c.execute('SELECT MAX(cpu_percent) FROM process_samples;')
row = c.fetchone()
print(f'{row[0]:.1f}' if row and row[0] is not None else '0.0')
")

echo "  Peak CPU recorded during sandbox run: ${PEAK_CPU}%"

if (( $(echo "${PEAK_CPU} > 0.0" | bc -l) )); then
    pass "Live CPU usage detected (> 0%): ${PEAK_CPU}%"
else
    fail "Live CPU usage was 0%"
fi

# Clean up temporary test databases
rm -f "${TEST_DB}" "${LIVE_DB}" /tmp/sentry_live_test.log

# ── Summary ──────────────────────────────────────────────────────────

header "Phase 4 Test Summary"
echo "  Total : ${TOTAL}"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo "═══════════════════════════════════════════════"

if [ "${FAIL}" -eq 0 ]; then
    echo "  All Phase 4 tests PASSED."
    exit 0
else
    echo "  Some Phase 4 tests FAILED."
    exit 1
fi
