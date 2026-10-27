#!/bin/bash
# test_phase7.sh — Automated tests for Phase 7 (Risk Scoring Engine)
#
# Usage: sudo bash test_phase7.sh [bin-dir]
#
# Verifies:
#   7.1  Unit tests for explainable point-based rules (CPU, RSS, fork, files, network, seccomp)
#   7.2  Composite risk score calculation & clamping [0, 100]
#   7.3  Threat band classifications (NORMAL, LOW, MEDIUM, HIGH, CRITICAL)
#   7.4  Live baseline run produces NORMAL risk band
#   7.5  Live burst file stress test triggers elevated risk band and rule traceability
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
    echo "Error: python3 is required for Phase 7 risk scoring."; exit 1
fi

if [ ! -f "${BINDIR}/sentry_sandbox_v3" ]; then
    echo "Error: ${BINDIR}/sentry_sandbox_v3 not found. Run 'make'."; exit 1
fi

echo "  Binary dir   : ${BINDIR}"
echo "  Sandbox root : ${SANDBOX_ROOT}"
echo "  Python       : $(python3 --version)"

# ── Test 7.1–7.3: Python RiskEngine Unit Tests ───────────────────────

header "Test 7.1–7.3 — RiskEngine Rules, Composition & Band Mapping"

export PYTHONPATH="$(pwd)/..:$(pwd)"
python3 -m unittest sentry.tests.test_risk_engine
if [ $? -eq 0 ]; then
    pass "RiskEngine unit tests passed (rule triggers, composition, band mapping, SQLite)"
else
    fail "RiskEngine unit tests failed"
fi

# ── Test 7.4: Live Baseline Execution (NORMAL band) ──────────────────

header "Test 7.4 — Live Baseline Execution (Expected Band: NORMAL)"

BASE_DB="test_phase7_base.db"
rm -f "${BASE_DB}" /tmp/sentry_risk_base.log

python3 -u cli/sentry.py run /bin/echo "clean baseline process" \
    --profile normal \
    --seccomp standard \
    --db "${BASE_DB}" \
    --interval 0.3 > /tmp/sentry_risk_base.log 2>&1

cat /tmp/sentry_risk_base.log

BASE_SCORE=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${BASE_DB}')
c = conn.cursor()
c.execute('SELECT MAX(score) FROM risk_scores;')
row = c.fetchone()
print(row[0] if row and row[0] is not None else 0)
")

BASE_BAND=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${BASE_DB}')
c = conn.cursor()
c.execute('SELECT band FROM risk_scores ORDER BY score DESC LIMIT 1;')
row = c.fetchone()
print(row[0] if row and row[0] is not None else 'NORMAL')
")

echo "  Baseline score: ${BASE_SCORE} | Band: ${BASE_BAND}"

if [ "${BASE_SCORE}" -le 20 ] && [ "${BASE_BAND}" = "NORMAL" ]; then
    pass "Quiet baseline process remained in NORMAL threat band (score: ${BASE_SCORE})"
else
    fail "Baseline process exceeded NORMAL threshold: score=${BASE_SCORE}, band=${BASE_BAND}"
fi

# ── Test 7.5: Live Threat Execution (Elevated band) ──────────────────

header "Test 7.5 — Live Threat Execution (Expected Band: Elevated / HIGH)"

THREAT_DB="test_phase7_threat.db"
rm -f "${THREAT_DB}" /tmp/sentry_risk_threat.log

python3 -u cli/sentry.py run /bin/stress_files 150 /tmp \
    --profile normal \
    --seccomp standard \
    --db "${THREAT_DB}" \
    --interval 0.3 > /tmp/sentry_risk_threat.log 2>&1

cat /tmp/sentry_risk_threat.log

THREAT_SCORE=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${THREAT_DB}')
c = conn.cursor()
c.execute('SELECT MAX(score) FROM risk_scores;')
row = c.fetchone()
print(row[0] if row and row[0] is not None else 0)
")

THREAT_BAND=$(python3 -c "
import sqlite3
conn = sqlite3.connect('${THREAT_DB}')
c = conn.cursor()
c.execute('SELECT band FROM risk_scores ORDER BY score DESC LIMIT 1;')
row = c.fetchone()
print(row[0] if row and row[0] is not None else 'NORMAL')
")

RULES_LOGGED=$(python3 -c "
import sqlite3, json
conn = sqlite3.connect('${THREAT_DB}')
c = conn.cursor()
c.execute('SELECT triggered_rules FROM risk_scores WHERE score > 0 ORDER BY score DESC LIMIT 1;')
row = c.fetchone()
if row and row[0]:
    rules = json.loads(row[0])
    print(', '.join(r['rule_name'] for r in rules))
else:
    print('NONE')
")

echo "  Threat score: ${THREAT_SCORE} | Band: ${THREAT_BAND}"
echo "  Triggered rules: ${RULES_LOGGED}"

if [ "${THREAT_SCORE}" -gt 20 ]; then
    pass "Malicious behavior pushed risk score into elevated band (${THREAT_BAND}, score: ${THREAT_SCORE})"
else
    fail "Threat test did not trigger elevated risk score: ${THREAT_SCORE}"
fi

if [ "${RULES_LOGGED}" != "NONE" ]; then
    pass "Traceable rule triggers logged in SQLite: ${RULES_LOGGED}"
else
    fail "No rule explanations recorded in SQLite"
fi

# Clean up temporary test databases
rm -f "${BASE_DB}" "${THREAT_DB}" /tmp/sentry_risk_base.log /tmp/sentry_risk_threat.log

# ── Summary ──────────────────────────────────────────────────────────

header "Phase 7 Test Summary"
echo "  Total : ${TOTAL}"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo "═══════════════════════════════════════════════"

if [ "${FAIL}" -eq 0 ]; then
    echo "  All Phase 7 tests PASSED."
    exit 0
else
    echo "  Some Phase 7 tests FAILED."
    exit 1
fi
