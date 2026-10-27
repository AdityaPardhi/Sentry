#!/bin/bash
# test_phase10.sh — Automated tests for Phase 10 (Formal Digital Forensics & Incident Logging)
#
# Usage: sudo bash test_phase10.sh [bin-dir]
#
# Verifies:
#   10.1 Consolidated single incidents schema with full forensic telemetry
#   10.2 Auto-populated incident records on security events with executable and timestamps
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
    echo "Error: python3 is required for Phase 10 forensic reporting."; exit 1
fi

if [ ! -f "${BINDIR}/sentry_sandbox_v3" ]; then
    echo "Error: ${BINDIR}/sentry_sandbox_v3 not found. Run 'make'."; exit 1
fi

echo "  Binary dir   : ${BINDIR}"
echo "  Sandbox root : ${SANDBOX_ROOT}"
echo "  Python       : $(python3 --version)"

# ── Test 10.1: Consolidated Incident Schema Verification ─────────────

header "Test 10.1 — Consolidated Forensic Schema Verification"

TEST_DB="test_phase10_schema.db"
rm -f "${TEST_DB}"

SCHEMA_CHECK=$(python3 -c "
import sys, os
sys.path.insert(0, os.getcwd())
from db.database import SentryDB

db = SentryDB('${TEST_DB}')
with db.get_connection() as conn:
    cols = [col[1] for col in conn.execute('PRAGMA table_info(incidents);').fetchall()]
    required = [
        'incident_id', 'pid', 'executable', 'start_time', 'detection_time',
        'cpu_percent', 'rss_kb', 'child_count', 'file_write_rate',
        'connection_attempts', 'risk_score', 'risk_band', 'action_taken',
        'recheck_metric', 'resolution'
    ]
    missing = [c for c in required if c not in cols]
    if missing:
        print('MISSING: ' + ', '.join(missing))
    else:
        print('OK')
")

if [ "${SCHEMA_CHECK}" = "OK" ]; then
    pass "Consolidated incident schema contains all 15 required forensic telemetry fields"
else
    fail "Incident schema missing fields: ${SCHEMA_CHECK}"
fi

# ── Test 10.2: Live Forensic Incident Population ─────────────────────

header "Test 10.2 — Live Sandboxed Forensic Incident Generation"

LIVE_DB="test_phase10_live.db"
rm -f "${LIVE_DB}" /tmp/sentry_p10_test.log

echo "[*] Launching stress_files to produce forensic incident record..."
python3 -u cli/sentry.py run /bin/stress_files 150 /tmp \
    --profile normal \
    --seccomp standard \
    --db "${LIVE_DB}" \
    --interval 0.3 > /tmp/sentry_p10_test.log 2>&1

cat /tmp/sentry_p10_test.log

# Verify forensic record fields in DB
FORENSIC_CHECK=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${LIVE_DB}')
c = conn.cursor()
c.execute('SELECT executable, risk_score, risk_band, action_taken, file_write_rate, resolution FROM incidents ORDER BY incident_id DESC LIMIT 1;')
row = c.fetchone()
if row:
    print(f'{row[0]} | score={row[1]} | band={row[2]} | action={row[3]} | rate={row[4]} | res={row[5]}')
else:
    print('NONE')
")

echo "  Recorded forensic event: ${FORENSIC_CHECK}"

if [ "${FORENSIC_CHECK}" != "NONE" ] && [[ "${FORENSIC_CHECK}" == *"/bin/stress_files"* ]]; then
    pass "Forensic incident properly captured target executable and telemetry: ${FORENSIC_CHECK}"
else
    fail "Forensic incident record incomplete: ${FORENSIC_CHECK}"
fi

# Clean up
rm -f "${TEST_DB}" "${LIVE_DB}" /tmp/sentry_p10_test.log

# ── Summary ──────────────────────────────────────────────────────────

header "Phase 10 Test Summary"
echo "  Total : ${TOTAL}"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo "═══════════════════════════════════════════════"

if [ "${FAIL}" -eq 0 ]; then
    echo "  All Phase 10 tests PASSED."
    exit 0
else
    echo "  Some Phase 10 tests FAILED."
    exit 1
fi
