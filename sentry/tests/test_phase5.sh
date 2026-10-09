#!/bin/bash
# test_phase5.sh — Automated tests for Phase 5 (File Behavior Monitoring)
#
# Usage: sudo bash test_phase5.sh [bin-dir]
#
# Verifies:
#   5.1  File create, modify, delete & directory tracking via inotify
#   5.2  Files-per-minute rate calculation under burst file operations
#   5.3  SQLite persistence in file_events & file_samples tables
#   5.4  Integration: live file monitoring during sandboxed execution

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
    echo "Error: python3 is required for Phase 5 monitoring."; exit 1
fi

if [ ! -f "${BINDIR}/sentry_sandbox_v3" ]; then
    echo "Error: ${BINDIR}/sentry_sandbox_v3 not found. Run 'make'."; exit 1
fi

# Ensure stress_files binary is compiled and installed into sandbox root
if [ ! -f "${BINDIR}/stress_files" ]; then
    gcc -O2 -o "${BINDIR}/stress_files" tests/stress_files.c
fi

if [ -d "${SANDBOX_ROOT}/bin" ]; then
    cp -f "${BINDIR}/stress_files" "${SANDBOX_ROOT}/bin/stress_files"
    chmod 755 "${SANDBOX_ROOT}/bin/stress_files"
fi

echo "  Binary dir   : ${BINDIR}"
echo "  Sandbox root : ${SANDBOX_ROOT}"
echo "  Python       : $(python3 --version)"

# ── Test 5.1–5.3: Python FileMonitor Unit & Rate Tests ──────────────

header "Test 5.1–5.3 — FileMonitor Lifecycle & Rate Spike"

TEST_DB="test_phase5_temp.db"
rm -f "${TEST_DB}"

python3 tests/test_file_monitor.py
if [ $? -eq 0 ]; then
    pass "FileMonitor correctly detects file CRUD operations, watches subdirectories, and computes rate"
else
    fail "FileMonitor test suite failed"
fi

# ── Test 5.4: Live File Monitoring inside Sandbox ───────────────────

header "Test 5.4 — End-to-End Sandboxed File Activity Monitoring"

LIVE_DB="test_phase5_live.db"
rm -f "${LIVE_DB}"

# Run sentry CLI to launch stress_files inside sandbox with concurrent file monitoring
echo "[*] Launching stress_files (150 files) in sandbox via cli/sentry.py..."
python3 -u cli/sentry.py run /bin/stress_files 150 /tmp \
    --profile normal \
    --seccomp standard \
    --db "${LIVE_DB}" \
    --interval 0.3 > /tmp/sentry_file_test.log 2>&1

cat /tmp/sentry_file_test.log

# Verify database exists
if [ -f "${LIVE_DB}" ]; then
    pass "Telemetry database was created"
else
    fail "Telemetry database was not created"
fi

# Check file events recorded
EVENT_COUNT=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${LIVE_DB}')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM file_events;')
print(c.fetchone()[0])
")

echo "  Logged file events in ${LIVE_DB}: ${EVENT_COUNT}"

if [ "${EVENT_COUNT}" -ge 50 ]; then
    pass "Logged ${EVENT_COUNT} file events (creates/modifies/deletes)"
else
    fail "Expected at least 50 file events, got ${EVENT_COUNT}"
fi

# Check peak file rate recorded
PEAK_RATE=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${LIVE_DB}')
c = conn.cursor()
c.execute('SELECT MAX(file_write_rate) FROM file_samples;')
row = c.fetchone()
print(f'{row[0]:.1f}' if row and row[0] is not None else '0.0')
")

echo "  Peak file rate recorded: ${PEAK_RATE} files/min"

if (( $(echo "${PEAK_RATE} > 20.0" | bc -l) )); then
    pass "Elevated file write rate detected (> 20 files/min): ${PEAK_RATE} files/min"
else
    fail "Peak file write rate was too low: ${PEAK_RATE}"
fi

# Clean up temporary test databases
rm -f "${TEST_DB}" "${LIVE_DB}" /tmp/sentry_file_test.log

# ── Summary ──────────────────────────────────────────────────────────

header "Phase 5 Test Summary"
echo "  Total : ${TOTAL}"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo "═══════════════════════════════════════════════"

if [ "${FAIL}" -eq 0 ]; then
    echo "  All Phase 5 tests PASSED."
    exit 0
else
    echo "  Some Phase 5 tests FAILED."
    exit 1
fi
