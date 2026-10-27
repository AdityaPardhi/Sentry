#!/usr/bin/env bash
# test_phase12.sh — SENTRY Phase 12: Comparison / Evaluation Mode
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
echo " SENTRY — Phase 12 Evaluation & Comparison Test"
echo "═══════════════════════════════════════════════"

REPORT_OUT="/tmp/sentry_comparison_test.md"
rm -f "$REPORT_OUT"

# Step 12.1: Verify evaluation script exists
echo ""
echo "[*] Step 12.1: Validating Evaluation Harness..."
if [ -f "tests/evaluate_comparison.py" ]; then
    pass "tests/evaluate_comparison.py exists"
else
    fail "tests/evaluate_comparison.py missing"
fi

# Step 12.2: Run evaluation harness
echo ""
echo "[*] Step 12.2: Executing Quantified Comparison (Protected vs Unprotected)..."
if python3 -u tests/evaluate_comparison.py --output "$REPORT_OUT"; then
    pass "Evaluation comparison harness executed successfully"
else
    fail "Evaluation comparison harness failed"
fi

# Step 12.3: Verify generated report artifact
echo ""
echo "[*] Step 12.3: Validating Generated Comparison Report..."
if [ -f "$REPORT_OUT" ] && grep -q "Containment Improvement %" "$REPORT_OUT"; then
    pass "Comparison report artifact generated with quantified containment percentages"
    echo ""
    echo "── Report Preview ──────────────────────────────"
    cat "$REPORT_OUT"
    echo "────────────────────────────────────────────────"
else
    fail "Comparison report artifact missing or incomplete"
fi

echo ""
echo "═══════════════════════════════════════════════"
echo " Phase 12 Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════"

rm -f "$REPORT_OUT"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
