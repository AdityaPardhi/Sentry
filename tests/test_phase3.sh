#!/bin/bash
# test_phase3.sh — Automated tests for Phase 3 (seccomp syscall filtering)
#
# Usage: sudo bash test_phase3.sh [bin-dir]
#
# Verifies:
#   3.1  Seccomp filter loads without error
#   3.2  A blocked syscall (socket AF_INET in minimal mode) kills the process
#   3.3  Standard mode: ls, cat, echo run correctly inside the sandbox

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
if [ ! -f "${BINDIR}/sentry_sandbox_v3" ]; then
    echo "Error: ${BINDIR}/sentry_sandbox_v3 not found. Run 'make'."; exit 1
fi
if [ ! -d "${SANDBOX_ROOT}" ]; then
    echo "Error: sandbox root ${SANDBOX_ROOT} not found."; exit 1
fi

echo "  Binary dir   : ${BINDIR}"
echo "  Sandbox root : ${SANDBOX_ROOT}"

export SENTRY_ROOT="${SANDBOX_ROOT}"

# ── Test 3.1: Seccomp filter loads (standard mode + echo) ────────────

header "Test 3.1 — Seccomp Filter Loads (standard mode)"

output=$(
    "${BINDIR}/sentry_sandbox_v3" run \
        /bin/echo "seccomp test" \
        --profile normal \
        --seccomp standard \
    2>&1
)
echo "$output"

if echo "$output" | grep -q "Seccomp filter active"; then
    pass "Seccomp filter reported as active"
else
    fail "Seccomp filter did not report as active"
fi

if echo "$output" | grep -q "seccomp test"; then
    pass "/bin/echo ran correctly under standard seccomp"
else
    fail "/bin/echo did not produce output under standard seccomp"
fi

# ── Test 3.2: Blocked syscall kills the process ───────────────────────

header "Test 3.2 — Blocked Syscall → SIGSYS (minimal mode)"

# test_seccomp_block calls socket(AF_INET) which is NOT in the minimal allow-list.
# The process should be killed with SIGSYS (signal 31).

if [ ! -f "${SANDBOX_ROOT}/bin/test_seccomp_block" ]; then
    echo "  (Skipping: test_seccomp_block not in sandbox root — run make install-tests)"
else
    output=$(
        "${BINDIR}/sentry_sandbox_v3" run \
            /bin/test_seccomp_block \
            --profile normal \
            --seccomp minimal \
        2>&1
    )
    echo "$output"

    # The sandbox should report SIGSYS (signal 31)
    if echo "$output" | grep -qi "SIGSYS\|signal 31\|blocked syscall"; then
        pass "Process killed with SIGSYS — seccomp block confirmed"
    else
        fail "Expected SIGSYS but got different termination (seccomp may not be blocking)"
    fi

    # The output from after the socket() call should NOT appear
    if echo "$output" | grep -q "socket.*succeeded"; then
        fail "socket() succeeded — seccomp filter did NOT block it"
    else
        pass "socket(AF_INET) did not succeed inside minimal sandbox"
    fi
fi

# ── Test 3.3: Standard mode — ordinary programs run correctly ─────────

header "Test 3.3 — Standard Mode: Ordinary Programs"

# Test ls /
echo "[Test] ls / inside sandbox (standard mode):"
output=$(
    "${BINDIR}/sentry_sandbox_v3" run \
        /bin/ls / \
        --seccomp standard \
    2>&1
)
echo "$output"

if echo "$output" | grep -q "bin"; then
    pass "ls / ran correctly under standard seccomp"
else
    fail "ls / failed under standard seccomp"
fi

# Test cat /etc/hostname
echo "[Test] cat /etc/hostname inside sandbox:"
output=$(
    "${BINDIR}/sentry_sandbox_v3" run \
        /bin/cat /etc/hostname \
        --seccomp standard \
    2>&1
)
echo "$output"

if echo "$output" | grep -qi "sandbox\|hostname\|linux"; then
    pass "cat /etc/hostname ran correctly"
else
    fail "cat /etc/hostname failed under standard seccomp"
fi

# Test echo
echo "[Test] echo inside sandbox:"
output=$(
    "${BINDIR}/sentry_sandbox_v3" run \
        /bin/echo "hello from seccomp sandbox" \
        --seccomp standard \
    2>&1
)
echo "$output"

if echo "$output" | grep -q "hello from seccomp sandbox"; then
    pass "echo ran correctly under standard seccomp"
else
    fail "echo failed under standard seccomp"
fi

# ── Summary ──────────────────────────────────────────────────────────

header "Test Summary"
echo "  Total : ${TOTAL}"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo ""
if [ "${FAIL}" -eq 0 ]; then
    echo "  ★ All Phase 3 tests passed!"
else
    echo "  ⚠ Some tests failed. Review output above."
fi
echo ""
