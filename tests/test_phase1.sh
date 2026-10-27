#!/bin/bash
# test_phase1.sh — Automated tests for Phase 1 (namespace isolation)
#
# Usage: sudo bash test_phase1.sh [bin-dir]
#        Default bin-dir: bin
#
# Runs each step's binary and verifies the isolation is working.

set -uo pipefail

BINDIR="${1:-bin}"
SANDBOX_ROOT="${SENTRY_ROOT:-/opt/sentry/sandbox-root}"
PASS=0
FAIL=0
TOTAL=0

# ── Helpers ──────────────────────────────────────────────────────────

pass() {
    PASS=$((PASS + 1))
    TOTAL=$((TOTAL + 1))
    echo "  ✓ PASS: $1"
}

fail() {
    FAIL=$((FAIL + 1))
    TOTAL=$((TOTAL + 1))
    echo "  ✗ FAIL: $1"
}

header() {
    echo ""
    echo "═══════════════════════════════════════════════"
    echo " $1"
    echo "═══════════════════════════════════════════════"
}

# ── Preconditions ────────────────────────────────────────────────────

header "Preconditions"

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: tests must be run as root (sudo)."
    exit 1
fi

if [ ! -f "${BINDIR}/sandbox_pid" ]; then
    echo "Error: binaries not found in ${BINDIR}."
    echo "Run 'make' first."
    exit 1
fi

if [ ! -d "${SANDBOX_ROOT}" ]; then
    echo "Error: sandbox root ${SANDBOX_ROOT} not found."
    echo "Run 'make setup' first."
    exit 1
fi

echo "  Binary dir   : ${BINDIR}"
echo "  Sandbox root : ${SANDBOX_ROOT}"

# ── Test 1.1: PID namespace ──────────────────────────────────────────

header "Test 1.1 — PID Namespace"

# The child should report PID 1 inside the namespace.
output=$("${BINDIR}/sandbox_pid" /bin/echo "hello from PID namespace" 2>&1)
echo "$output"

if echo "$output" | grep -q "PID (inside namespace) = 1"; then
    pass "Child sees itself as PID 1"
else
    fail "Child does not see itself as PID 1"
fi

if echo "$output" | grep -q "hello from PID namespace"; then
    pass "Command executed successfully inside PID namespace"
else
    fail "Command did not execute inside PID namespace"
fi

# ── Test 1.2: Mount namespace ────────────────────────────────────────

header "Test 1.2 — Mount Namespace"

# ls / inside the sandbox should show the sandbox-root contents,
# not the real root filesystem.  We check that /etc/hostname contains
# "sandbox" (as set by setup_sandbox_root.sh) if using manual copy.
output=$("${BINDIR}/sandbox_mount" "${SANDBOX_ROOT}" /bin/ls / 2>&1)
echo "$output"

if echo "$output" | grep -q "bin"; then
    pass "Sandbox root has a bin directory"
else
    fail "Sandbox root is missing bin directory"
fi

# The sandbox should NOT contain host-only paths
if echo "$output" | grep -qv "home\|snap\|boot"; then
    pass "Sandbox does not expose host-specific directories"
else
    fail "Sandbox may be leaking host directories"
fi

# ── Test 1.3: Network namespace ──────────────────────────────────────

header "Test 1.3 — Network Namespace"

# ping 127.0.0.1 should work (loopback is up)
# We use -c 1 -W 2 for a single quick ping with 2s timeout.
# Note: this test requires ping to be available in the sandbox root.
if [ -f "${SANDBOX_ROOT}/bin/ping" ] || [ -f "${SANDBOX_ROOT}/usr/bin/ping" ]; then
    output=$("${BINDIR}/sandbox_net" "${SANDBOX_ROOT}" /bin/ping -c 1 -W 2 127.0.0.1 2>&1) || true
    echo "$output"

    if echo "$output" | grep -qi "1 received\|1 packets received\| 0% packet loss"; then
        pass "Loopback ping (127.0.0.1) succeeded"
    else
        fail "Loopback ping (127.0.0.1) failed"
    fi
else
    echo "  (skipping loopback ping test — ping not in sandbox root)"
fi

# ping 8.8.8.8 should fail (no external connectivity)
if [ -f "${SANDBOX_ROOT}/bin/ping" ] || [ -f "${SANDBOX_ROOT}/usr/bin/ping" ]; then
    output=$("${BINDIR}/sandbox_net" "${SANDBOX_ROOT}" /bin/ping -c 1 -W 2 8.8.8.8 2>&1) || true
    echo "$output"

    if echo "$output" | grep -qi "100% packet loss\|Network is unreachable\|sendmsg: Network is unreachable"; then
        pass "External ping (8.8.8.8) correctly blocked"
    else
        fail "External ping (8.8.8.8) was NOT blocked — network leaking!"
    fi
else
    echo "  (skipping external ping test — ping not in sandbox root)"
fi

# ── Test 1.4: Combined sandbox ───────────────────────────────────────

header "Test 1.4 — Combined Sandbox (sentry_sandbox run)"

export SENTRY_ROOT="${SANDBOX_ROOT}"
output=$("${BINDIR}/sentry_sandbox" run /bin/echo "sentry works" 2>&1)
echo "$output"

if echo "$output" | grep -q "sentry works"; then
    pass "sentry_sandbox run executed command successfully"
else
    fail "sentry_sandbox run did not execute command"
fi

if echo "$output" | grep -q "PID namespace isolated"; then
    pass "PID namespace isolation confirmed"
else
    fail "PID namespace isolation not reported"
fi

if echo "$output" | grep -q "Mount namespace isolated"; then
    pass "Mount namespace isolation confirmed"
else
    fail "Mount namespace isolation not reported"
fi

if echo "$output" | grep -q "Network namespace isolated"; then
    pass "Network namespace isolation confirmed"
else
    fail "Network namespace isolation not reported"
fi

# ── Summary ──────────────────────────────────────────────────────────

header "Test Summary"
echo "  Total : ${TOTAL}"
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo ""
if [ "${FAIL}" -eq 0 ]; then
    echo "  ★ All tests passed! Phase 1 is complete."
else
    echo "  ⚠ Some tests failed. Review output above."
fi
echo ""
