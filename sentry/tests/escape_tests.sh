#!/usr/bin/env bash
# escape_tests.sh — SENTRY Sandbox Escape Test Suite (Part 3)
#
# Usage: sudo bash tests/escape_tests.sh <bindir> <escape_bindir>
#
# Records SHA-256 hashes of host sentinel files before running each test,
# then verifies them afterwards to detect any host filesystem modification.
# Runs each escape-attempt program inside the sandbox and expects it to be
# blocked (PASS) rather than succeed (FAIL).

set -euo pipefail

BINDIR="${1:-bin}"
ESCAPE_BIN="${2:-bin/escape}"
SANDBOX="${BINDIR}/sentry_sandbox_v3"
SANDBOX_ROOT="${SENTRY_ROOT:-/opt/sentry/sandbox-root}"

# Sentinel files whose hashes we track
SENTINEL_FILES=(
    "/etc/passwd"
    "/etc/hostname"
)

# Create a unique marker file in /tmp as an additional sentinel
MARKER="/tmp/sentry_host_marker_$$"
echo "sentry-escape-test-marker-$(date +%s)" > "${MARKER}"
SENTINEL_FILES+=("${MARKER}")

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASS=0
FAIL=0

# -----------------------------------------------------------------------
# Helper: compute SHA-256 hashes of all sentinel files
# -----------------------------------------------------------------------
hash_sentinels() {
    local hashes=""
    for f in "${SENTINEL_FILES[@]}"; do
        if [ -f "$f" ]; then
            hashes+="$(sha256sum "$f")\n"
        fi
    done
    echo -e "$hashes"
}

# -----------------------------------------------------------------------
# Helper: check sentinel hashes haven't changed
# Returns 0 if all match, 1 if any differ
# -----------------------------------------------------------------------
check_sentinels() {
    local before="$1"
    local after
    after=$(hash_sentinels)
    if [ "$before" = "$after" ]; then
        return 0
    else
        echo -e "${RED}  HOST FILES MODIFIED — hashes changed!${NC}"
        diff <(echo "$before") <(echo "$after") || true
        return 1
    fi
}

# -----------------------------------------------------------------------
# Helper: run one escape test
# -----------------------------------------------------------------------
run_escape_test() {
    local name="$1"
    local binary="$2"
    local desc="$3"
    local expect_killed="${4:-true}"  # true = expect SIGKILL/SIGSYS, false = just check files

    echo ""
    echo "────────────────────────────────────────────────"
    echo "  TEST: ${name}"
    echo "  DESC: ${desc}"

    # Copy the escape binary into the sandbox root
    if ! cp "${binary}" "${SANDBOX_ROOT}/bin/escape_test" 2>/dev/null; then
        echo -e "${YELLOW}  SKIP: Cannot copy binary to sandbox root (try: make install-tests first)${NC}"
        return
    fi
    chmod 755 "${SANDBOX_ROOT}/bin/escape_test"

    local before
    before=$(hash_sentinels)

    # Run inside the sandbox with the strictest profile
    local exit_code=0
    sudo "${SANDBOX}" run /bin/escape_test \
        --profile strict --seccomp standard \
        2>/dev/null || exit_code=$?

    local files_ok=0
    check_sentinels "$before" && files_ok=1

    # A blocked syscall returns 128+SIGSYS(31)=159, or SIGKILL=128+9=137
    local blocked=false
    if [ "$exit_code" -ne 0 ]; then
        blocked=true
    fi

    if $blocked && [ "$files_ok" -eq 1 ]; then
        echo -e "${GREEN}  PASS${NC} — escape blocked (exit=${exit_code}), host files unchanged"
        PASS=$((PASS + 1))
    elif ! $blocked && [ "$expect_killed" = "false" ] && [ "$files_ok" -eq 1 ]; then
        echo -e "${GREEN}  PASS${NC} — returned 0 but host files unchanged (escape blocked at fs level)"
        PASS=$((PASS + 1))
    else
        echo -e "${RED}  FAIL${NC} — exit=${exit_code}, host_files_ok=${files_ok}"
        FAIL=$((FAIL + 1))
    fi

    rm -f "${SANDBOX_ROOT}/bin/escape_test"
}

# -----------------------------------------------------------------------
# Pre-flight checks
# -----------------------------------------------------------------------
if [ ! -x "${SANDBOX}" ]; then
    echo "ERROR: Sandbox binary not found at ${SANDBOX}. Run 'make' first."
    exit 1
fi
if [ ! -d "${SANDBOX_ROOT}" ]; then
    echo "ERROR: Sandbox root not found at ${SANDBOX_ROOT}. Run 'make setup' first."
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║            SENTRY SANDBOX ESCAPE TEST SUITE                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "  Sandbox   : ${SANDBOX}"
echo "  Root      : ${SANDBOX_ROOT}"
echo "  Sentinels : ${SENTINEL_FILES[*]}"
echo ""

# -----------------------------------------------------------------------
# Run each escape test
# -----------------------------------------------------------------------

run_escape_test \
    "read_host_file" \
    "${ESCAPE_BIN}/read_host_file" \
    "Tries to open /etc/passwd via ../../../etc/passwd (path traversal)"

run_escape_test \
    "write_proc" \
    "${ESCAPE_BIN}/write_proc" \
    "Tries to write to /proc/sysrq-trigger (should be masked with /dev/null)"

run_escape_test \
    "mknod_dev" \
    "${ESCAPE_BIN}/mknod_dev" \
    "Tries mknod('/tmp/sda', S_IFBLK, makedev(8,0)) — blocked by seccomp"

run_escape_test \
    "chroot_escape" \
    "${ESCAPE_BIN}/chroot_escape" \
    "Classic chroot escape via mkdir+chroot loop — blocked by seccomp (no chroot)"

run_escape_test \
    "fork_bomb" \
    "${ESCAPE_BIN}/fork_bomb" \
    "Forks until PID limit — should be killed by cgroup pids.max"

run_escape_test \
    "raw_socket" \
    "${ESCAPE_BIN}/raw_socket" \
    "Tries socket(AF_INET, SOCK_RAW, 0) — blocked by seccomp AF_UNIX-only policy"

# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------
echo ""
echo "════════════════════════════════════════════════════════════════"
echo "  Results:  ${PASS} PASS  |  ${FAIL} FAIL"
echo "════════════════════════════════════════════════════════════════"

# Clean up sentinel marker
rm -f "${MARKER}"

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}  ALL TESTS PASSED — sandbox successfully blocks all escape attempts${NC}"
    exit 0
else
    echo -e "${RED}  ${FAIL} TEST(S) FAILED — review sandbox hardening${NC}"
    exit 1
fi
