#!/bin/bash
# test_phase8.sh — Automated tests for Phase 8 (Automatic Incident Mitigation)
#
# Usage: sudo bash test_phase8.sh [bin-dir]
#
# Verifies:
#   8.1  Tier 1 automated cgroup throttling on LOW/MEDIUM (halve cpu.max)
#   8.2  Tier 2 aggressive cgroup throttling on HIGH (cut cpu.max to 5%)
#   8.3  Tier 3 process termination (SIGKILL) on CRITICAL
#   8.4  SQLite persistence in incidents table with action traceability
#   8.5  Live end-to-end sandboxed threat mitigation
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
    echo "Error: python3 is required for Phase 8 response engine."; exit 1
fi

if [ ! -f "${BINDIR}/sentry_sandbox_v3" ]; then
    echo "Error: ${BINDIR}/sentry_sandbox_v3 not found. Run 'make'."; exit 1
fi

echo "  Binary dir   : ${BINDIR}"
echo "  Sandbox root : ${SANDBOX_ROOT}"
echo "  Python       : $(python3 --version)"

# ── Test 8.1–8.4: ResponseEngine Unit Tests ──────────────────────────

header "Test 8.1–8.4 — ResponseEngine Tier Actions & SQLite Persistence"

export PYTHONPATH="$(pwd)/..:$(pwd)"
python3 -m unittest sentry.tests.test_response_engine
if [ $? -eq 0 ]; then
    pass "ResponseEngine unit tests passed (Tier 1 cgroup halve, Tier 2 5% cap, Tier 3 SIGKILL, DB persistence)"
else
    fail "ResponseEngine unit tests failed"
fi

# ── Test 8.5: Live Automated Mitigation in Sandbox ───────────────────

header "Test 8.5 — Live End-to-End Automated Mitigation (cgroup throttle)"

LIVE_DB="test_phase8_live.db"
rm -f "${LIVE_DB}" /tmp/sentry_resp_test.log

echo "[*] Launching stress_files (150 files) in sandbox via cli/sentry.py..."
python3 -u cli/sentry.py run /bin/stress_files 150 /tmp \
    --profile normal \
    --seccomp standard \
    --db "${LIVE_DB}" \
    --interval 0.3 > /tmp/sentry_resp_test.log 2>&1

cat /tmp/sentry_resp_test.log

# Check incidents table
INCIDENT_COUNT=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${LIVE_DB}')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM incidents;')
print(c.fetchone()[0])
")

echo "  Logged mitigation incidents in ${LIVE_DB}: ${INCIDENT_COUNT}"

if [ "${INCIDENT_COUNT}" -ge 1 ]; then
    pass "Automated security incident recorded in SQLite (${INCIDENT_COUNT} actions)"
else
    fail "No incidents recorded in database"
fi

# Check action taken
ACTION_TAKEN=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${LIVE_DB}')
c = conn.cursor()
c.execute('SELECT action_taken, band, details FROM incidents ORDER BY id DESC LIMIT 1;')
row = c.fetchone()
if row:
    print(f'{row[0]} | {row[1]} | {row[2]}')
else:
    print('NONE')
")

echo "  Latest mitigation: ${ACTION_TAKEN}"

if [[ "${ACTION_TAKEN}" == *"THROTTLE"* ]] || [[ "${ACTION_TAKEN}" == *"KILL"* ]]; then
    pass "Tiered mitigation policy executed: ${ACTION_TAKEN}"
else
    fail "Expected throttling or termination action, got: ${ACTION_TAKEN}"
fi

# Clean up temporary test database
rm -f "${LIVE_DB}" /tmp/sentry_resp_test.log

# ── Summary ──────────────────────────────────────────────────────────

header "Phase 8 Test Summary"
echo "  Total : ${TOTAL}"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo "═══════════════════════════════════════════════"

if [ "${FAIL}" -eq 0 ]; then
    echo "  All Phase 8 tests PASSED."
    exit 0
else
    echo "  Some Phase 8 tests FAILED."
    exit 1
fi
