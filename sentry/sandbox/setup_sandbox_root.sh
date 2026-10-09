#!/bin/bash
# setup_sandbox_root.sh — Prepare a minimal filesystem for the sandbox.
#
# Creates /opt/sentry/sandbox-root with a minimal Debian/Ubuntu
# filesystem using debootstrap (preferred) or a manual copy fallback.
#
# Usage: sudo bash setup_sandbox_root.sh [target-dir]
#        Default target: /opt/sentry/sandbox-root

set -euo pipefail

SANDBOX_ROOT="${1:-/opt/sentry/sandbox-root}"

echo "=========================================="
echo " SENTRY — Sandbox Root Setup"
echo "=========================================="
echo "Target directory: ${SANDBOX_ROOT}"
echo ""

# --- Ensure we're root ---
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: this script must be run as root (sudo)."
    exit 1
fi

# --- Create target directory ---
mkdir -p "${SANDBOX_ROOT}"

# --- Method 1: debootstrap (preferred — full minimal Debian userland) ---
if command -v debootstrap &>/dev/null; then
    echo "[*] debootstrap found — creating a minimal Debian filesystem..."
    echo "    (This may take several minutes on the first run.)"
    echo ""

    # Use the codename of the running system, or fall back to "jammy"
    CODENAME=$(lsb_release -cs 2>/dev/null || echo "jammy")

    debootstrap --variant=minbase "${CODENAME}" "${SANDBOX_ROOT}" \
        http://archive.ubuntu.com/ubuntu/

    echo ""
    echo "[✓] debootstrap complete."
else
    echo "[*] debootstrap not found — using manual copy fallback."
    echo "    (Install debootstrap for a more complete sandbox filesystem:"
    echo "     sudo apt install debootstrap)"
    echo ""

    # --- Method 2: manual copy of essential binaries & libraries ---
    echo "[*] Copying essential directories..."

    # Create the directory structure
    for dir in bin sbin lib lib64 usr/bin usr/sbin usr/lib etc proc dev tmp; do
        mkdir -p "${SANDBOX_ROOT}/${dir}"
    done

    # List of essential utilities to copy
    CORE_BINS=(
        bash sh ls cat echo mkdir rm cp mv grep ps mount hostname
        ping env id whoami top head tail wc du find ip
    )

    echo "    Copying core binaries..."
    for cmd in "${CORE_BINS[@]}"; do
        src=$(type -P "$cmd" 2>/dev/null || which "$cmd" 2>/dev/null || true)
        if [ -n "$src" ] && [ -e "$src" ]; then
            real_src=$(realpath "$src" 2>/dev/null || readlink -f "$src" 2>/dev/null || echo "$src")
            # Remove any broken symlink or old file first
            rm -f "${SANDBOX_ROOT}/bin/$cmd" "${SANDBOX_ROOT}/usr/bin/$cmd"
            # Copy dereferenced binary to both /bin and /usr/bin so any path works
            cp -L "$real_src" "${SANDBOX_ROOT}/bin/$cmd" 2>/dev/null || true
            cp -L "$real_src" "${SANDBOX_ROOT}/usr/bin/$cmd" 2>/dev/null || true
            chmod 755 "${SANDBOX_ROOT}/bin/$cmd" 2>/dev/null || true
            chmod 755 "${SANDBOX_ROOT}/usr/bin/$cmd" 2>/dev/null || true
        fi
    done

    # Copy shared libraries needed by the binaries above.
    echo "    Copying shared libraries (this may take a moment)..."
    for bin in "${SANDBOX_ROOT}/bin"/*; do
        [ -f "$bin" ] || continue
        ldd "$bin" 2>/dev/null | grep -oP '(/[^ ]+)' | while read -r lib; do
            if [ -e "$lib" ]; then
                dest="${SANDBOX_ROOT}${lib}"
                mkdir -p "$(dirname "$dest")"
                cp -n -L "$lib" "$dest" 2>/dev/null || true
            fi
        done
    done

    # Ensure dynamic linker / interpreter is present
    for interp in /lib64/ld-linux* /lib/x86_64-linux-gnu/ld-linux* /usr/lib64/ld-linux* /usr/lib/x86_64-linux-gnu/ld-linux*; do
        if [ -e "$interp" ]; then
            dest="${SANDBOX_ROOT}${interp}"
            mkdir -p "$(dirname "$dest")"
            cp -n -L "$interp" "$dest" 2>/dev/null || true
        fi
    done

    mkdir -p "${SANDBOX_ROOT}/lib64"
    if [ ! -f "${SANDBOX_ROOT}/lib64/ld-linux-x86-64.so.2" ]; then
        found_ld=$(find /lib /usr/lib -name 'ld-linux-x86-64.so.2' 2>/dev/null | head -n 1 || true)
        if [ -n "$found_ld" ]; then
            cp -L "$found_ld" "${SANDBOX_ROOT}/lib64/ld-linux-x86-64.so.2" 2>/dev/null || true
        fi
    fi

    # Minimal /etc files
    echo "root:x:0:0:root:/root:/bin/bash" > "${SANDBOX_ROOT}/etc/passwd"
    echo "root:x:0:" > "${SANDBOX_ROOT}/etc/group"
    echo "sandbox" > "${SANDBOX_ROOT}/etc/hostname"

    # Create /dev/null and /dev/zero (mknod requires root)
    mknod -m 666 "${SANDBOX_ROOT}/dev/null"  c 1 3 2>/dev/null || true
    mknod -m 666 "${SANDBOX_ROOT}/dev/zero"  c 1 5 2>/dev/null || true
    mknod -m 666 "${SANDBOX_ROOT}/dev/urandom" c 1 9 2>/dev/null || true

    echo ""
    echo "[✓] Manual copy complete."
fi

echo ""
echo "=========================================="
echo " Sandbox root ready at: ${SANDBOX_ROOT}"
echo "=========================================="
echo ""
echo "Contents of sandbox root:"
ls -la "${SANDBOX_ROOT}"
echo ""
echo "You can now launch the sandbox:"
echo "  sudo ./sentry_sandbox run /bin/bash"
