#!/usr/bin/env bash
# test_phase11.sh — SENTRY Phase 11 Test Suite: Attack Replay Harness
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
cd "$BASE_DIR"

PASS=0
FAIL=0

pass() {
    echo -e "  \033[32m[PASS]\033[0m $1"
    PASS=$((PASS + 1))
}

fail() {
    echo -e "  \033[31m[FAIL]\033[0m $1"
    FAIL=$((FAIL + 1))
}

echo "═══════════════════════════════════════════════"
echo " SENTRY — Phase 11 Attack Replay Test Suite"
echo "═══════════════════════════════════════════════"

# Test 11.1: Verify attack generator scripts exist
echo ""
echo "[*] Step 11.1: Validating Attack Generator Scripts..."
if [ -f "tests/cpu_stress.py" ] && [ -f "tests/process_storm.py" ] && [ -f "tests/file_burst.py" ] && [ -f "tests/net_burst.py" ]; then
    pass "All attack generator scripts exist (cpu, process, file, network)"
else
    fail "One or more attack generator scripts missing"
fi

# Test 11.2: Verify master test runner exists
echo ""
echo "[*] Step 11.2: Validating Master Test Harness..."
if [ -f "tests/run_all.py" ]; then
    pass "Master attack replay harness tests/run_all.py exists"
else
    fail "Master test harness tests/run_all.py not found"
fi

# Test 11.3: Run master attack replay suite
echo ""
echo "[*] Step 11.3: Executing End-to-End Attack Replay Suite..."
DB_TEST="/tmp/sentry_phase11_test.db"
rm -f "$DB_TEST"

if python3 -u tests/run_all.py --db "$DB_TEST"; then
    pass "Master attack replay harness completed successfully with all detections"
else
    fail "One or more attack vectors failed detection or mitigation"
fi

echo ""
echo "═══════════════════════════════════════════════"
echo " Phase 11 Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════"

rm -f "$DB_TEST"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
