#!/bin/bash
# test_phase9.sh — Automated tests for Phase 9 (Recovery Loop & Escalation)
#
# Usage: sudo bash test_phase9.sh [bin-dir]
#
# Verifies:
#   9.1  Pre/post metric tracking across mitigation actions
#   9.2  Escalation state machine (RECOVERED vs ESCALATED)
#   9.3  Incident resolution lifecycle persistence in SQLite
#   9.4  Live sandboxed execution with automated recovery loop
#

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
    echo "Error: python3 is required for Phase 9 recovery loop."; exit 1
fi

if [ ! -f "${BINDIR}/sentry_sandbox_v3" ]; then
    echo "Error: ${BINDIR}/sentry_sandbox_v3 not found. Run 'make'."; exit 1
fi

echo "  Binary dir   : ${BINDIR}"
echo "  Sandbox root : ${SANDBOX_ROOT}"
echo "  Python       : $(python3 --version)"

# ── Test 9.1–9.3: Recovery Loop Unit Tests ───────────────────────────

header "Test 9.1–9.3 — Recovery State Machine & Escalation Unit Tests"

export PYTHONPATH="$(pwd)/..:$(pwd)"
python3 -m unittest sentry.tests.test_recovery_loop
if [ $? -eq 0 ]; then
    pass "Recovery loop unit tests passed (pre/post metrics, RECOVERED, ESCALATED, DB update)"
else
    fail "Recovery loop unit tests failed"
fi

# ── Test 9.4: Live End-to-End Recovery Loop Lifecycle ────────────────

header "Test 9.4 — Live Sandboxed Incident Recovery Lifecycle"

LIVE_DB="test_phase9_live.db"
rm -f "${LIVE_DB}" /tmp/sentry_p9_test.log

echo "[*] Launching stress_files in sandbox to trigger mitigation and recovery lifecycle..."
python3 -u cli/sentry.py run /bin/stress_files 150 /tmp \
    --profile normal \
    --seccomp standard \
    --db "${LIVE_DB}" \
    --interval 0.3 > /tmp/sentry_p9_test.log 2>&1

cat /tmp/sentry_p9_test.log

# Verify database exists
if [ -f "${LIVE_DB}" ]; then
    pass "Telemetry database was created"
else
    fail "Telemetry database was not created"
fi

# Check incident lifecycle fields in database
LIFECYCLE_RECORD=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${LIVE_DB}')
c = conn.cursor()
c.execute('SELECT action_taken, pre_metric, post_metric, resolution FROM incidents ORDER BY id DESC LIMIT 1;')
row = c.fetchone()
if row:
    print(f'{row[0]} | pre={row[1]:.1f} | post={row[2]:.1f} | res={row[3]}')
else:
    print('NONE')
")

echo "  Incident lifecycle: ${LIFECYCLE_RECORD}"

if [ "${LIFECYCLE_RECORD}" != "NONE" ]; then
    pass "Lifecycle record verified: ${LIFECYCLE_RECORD}"
else
    fail "No incident lifecycle records logged"
fi

# Clean up temporary test database
rm -f "${LIVE_DB}" /tmp/sentry_p9_test.log

# ── Summary ──────────────────────────────────────────────────────────

header "Phase 9 Test Summary"
echo "  Total : ${TOTAL}"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo "═══════════════════════════════════════════════"

if [ "${FAIL}" -eq 0 ]; then
    echo "  All Phase 9 tests PASSED."
    exit 0
else
    echo "  Some Phase 9 tests FAILED."
    exit 1
fi
