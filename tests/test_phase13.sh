#!/usr/bin/env bash
# test_phase13.sh — SENTRY Phase 13: Interface (CLI Status & Web Dashboard)
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
echo " SENTRY — Phase 13 Interface & Status Views"
echo "═══════════════════════════════════════════════"

# Step 13.1: Verify CLI Status View
echo ""
echo "[*] Step 13.1: Validating CLI Status Dashboard (sentry.py status --once)..."
STATUS_OUT=$(python3 -u cli/sentry.py status --once --db sentry.db)

if echo "$STATUS_OUT" | grep -q "STATUS DASHBOARD"; then
    pass "CLI status command executed successfully and rendered header"
else
    fail "CLI status command failed to render status dashboard"
fi

# Step 13.2: Verify Process Tree and Resource Telemetry rendered
echo ""
echo "[*] Step 13.2: Validating ASCII Telemetry & Process Tree Renderer..."
if echo "$STATUS_OUT" | grep -q "RESOURCE TELEMETRY" && echo "$STATUS_OUT" | grep -q "PROCESS HIERARCHY TREE"; then
    pass "ASCII Resource Telemetry & Process Hierarchy Tree rendered cleanly"
else
    fail "Process tree or resource telemetry section missing from status view"
fi

# Step 13.3: Web Dashboard is out-of-scope and removed per changes.md Part 2.
echo ""
echo "[*] Step 13.3: Web Dashboard omitted (out of scope per changes.md Part 2)"

echo ""
echo "═══════════════════════════════════════════════"
echo " Phase 13 Results: $PASS passed, $FAIL failed"
echo "═══════════════════════════════════════════════"

if [ $FAIL -gt 0 ]; then
    exit 1
fi
exit 0
