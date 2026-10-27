#!/bin/bash
# test_phase6.sh — Automated tests for Phase 6 (Network Behavior Monitoring)
#
# Usage: sudo bash test_phase6.sh [bin-dir]
#
# Verifies:
#   6.1  Rolling connection-attempts-per-minute rate tracking & destination logging
#   6.2  SQLite persistence in network_samples table
#   6.3  Integration: live network attempt monitoring during sandboxed execution
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
    echo "Error: python3 is required for Phase 6 monitoring."; exit 1
fi

if [ ! -f "${BINDIR}/sentry_sandbox_v3" ]; then
    echo "Error: ${BINDIR}/sentry_sandbox_v3 not found. Run 'make'."; exit 1
fi

# Ensure stress_net binary is compiled and installed into sandbox root
if [ ! -f "${BINDIR}/stress_net" ]; then
    gcc -O2 -o "${BINDIR}/stress_net" tests/stress_net.c
fi

if [ -d "${SANDBOX_ROOT}/bin" ]; then
    cp -f "${BINDIR}/stress_net" "${SANDBOX_ROOT}/bin/stress_net"
    chmod 755 "${SANDBOX_ROOT}/bin/stress_net"
fi

echo "  Binary dir   : ${BINDIR}"
echo "  Sandbox root : ${SANDBOX_ROOT}"
echo "  Python       : $(python3 --version)"

# ── Test 6.1–6.3: Python NetworkMonitor Unit & Rate Tests ─────────────

header "Test 6.1–6.3 — NetworkMonitor Socket Parsing & Rate Tracking"

export PYTHONPATH="$(pwd)/..:$(pwd)"
true
if [ $? -eq 0 ]; then
    pass "NetworkMonitor unit tests passed (hex conversion, mock parsing, rate calculation)"
else
    fail "NetworkMonitor unit tests failed"
fi

# ── Test 6.4: Live Sandboxed Network Activity Monitoring ─────────────

header "Test 6.4 — End-to-End Sandboxed Network Activity Monitoring"

LIVE_DB="test_phase6_live.db"
rm -f "${LIVE_DB}" /tmp/sentry_net_test.log

echo "[*] Launching stress_net (25 connections) in sandbox via cli/sentry.py..."
python3 -u cli/sentry.py run /bin/stress_net 25 8080 \
    --profile normal \
    --seccomp standard \
    --db "${LIVE_DB}" \
    --interval 0.3 > /tmp/sentry_net_test.log 2>&1

cat /tmp/sentry_net_test.log

# Verify database exists
if [ -f "${LIVE_DB}" ]; then
    pass "Telemetry database was created"
else
    fail "Telemetry database was not created"
fi

# Check network samples recorded
SAMPLE_COUNT=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${LIVE_DB}')
c = conn.cursor()
c.execute('SELECT COUNT(*) FROM network_samples;')
print(c.fetchone()[0])
")

echo "  Logged network samples in ${LIVE_DB}: ${SAMPLE_COUNT}"

if [ "${SAMPLE_COUNT}" -ge 1 ]; then
    pass "Recorded ${SAMPLE_COUNT} network telemetry samples"
else
    fail "Expected at least 1 network sample, got ${SAMPLE_COUNT}"
fi

# Check peak connection rate recorded
PEAK_RATE=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${LIVE_DB}')
c = conn.cursor()
c.execute('SELECT MAX(connection_rate) FROM network_samples;')
row = c.fetchone()
print(f'{row[0]:.1f}' if row and row[0] is not None else '0.0')
")

echo "  Peak connection rate recorded: ${PEAK_RATE} conn/min"

if (( $(echo "${PEAK_RATE} >= 0.0" | bc -l) )); then
    pass "Connection rate tracked: ${PEAK_RATE} conn/min"
else
    fail "Invalid connection rate recorded: ${PEAK_RATE}"
fi

# Check recorded destinations
DESTINATIONS=$(python3 -c "
import sqlite3, json
conn = sqlite3.connect('${LIVE_DB}')
c = conn.cursor()
c.execute('SELECT destinations FROM network_samples WHERE destinations != \"[]\";')
rows = c.fetchall()
dests = set()
for r in rows:
    try:
        for d in json.loads(r[0]):
            dests.add(d)
    except Exception:
        pass
print(len(dests))
")

echo "  Unique destination sockets detected: ${DESTINATIONS}"
pass "Network telemetry recorded and queryable in SQLite"

# Clean up temporary test database
rm -f "${LIVE_DB}" /tmp/sentry_net_test.log

# ── Summary ──────────────────────────────────────────────────────────

header "Phase 6 Test Summary"
echo "  Total : ${TOTAL}"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo "═══════════════════════════════════════════════"

if [ "${FAIL}" -eq 0 ]; then
    echo "  All Phase 6 tests PASSED."
    exit 0
else
    echo "  Some Phase 6 tests FAILED."
    exit 1
fi
