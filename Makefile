# Makefile for SENTRY sandbox
#
# Changes (changes.md):
#   - Old sandbox binaries (sandbox_pid, sandbox_mount, sandbox_net,
#     sentry_sandbox, sentry_sandbox_v2) removed — they are off-agenda.
#   - capset() is called via raw syscall(SYS_capset,...) — no -lcap needed.
#   - Added 'escape-test' target that runs tests/escape_tests.sh.
#   - 'bin/' prebuilt binaries should be built by make, not committed.
#
# Main targets:
#   all               Build the active sandbox binary and test helpers
#   escape-test       Run the escape test suite (requires sudo)
#   clean             Remove all built binaries
#   setup             Prepare the sandbox root filesystem (requires sudo)
#   install-tests     Copy test binaries into sandbox root /bin
#
# Legacy test targets (phase tests) are kept for regression:
#   test3 … test13

CC       = gcc
CFLAGS   = -Wall -Wextra -std=gnu11
LDFLAGS  =
SANDBOX  = sandbox
TESTS    = tests

# Output binaries
BINDIR   = bin

# Sandbox root (for install-tests target)
SANDBOX_ROOT ?= /opt/sentry/sandbox-root

.PHONY: all clean setup install-tests test escape-test \
        test3 test4 test5 test6 test7 test8 test10 test11 test12 test13 test-all \
        web web-stub demo demo-stub

all: $(BINDIR)/sentry_sandbox_v3 $(BINDIR)/test_seccomp_block \
     $(BINDIR)/stress_cpu $(BINDIR)/stress_mem $(BINDIR)/stress_fork \
     $(BINDIR)/stress_files $(BINDIR)/stress_net \
     $(BINDIR)/t1_clean $(BINDIR)/t2_file_drop $(BINDIR)/t3_secret_reader \
     $(BINDIR)/t4_network $(BINDIR)/t5_spawner

$(BINDIR):
	mkdir -p $(BINDIR)

# ── Main sandbox binary ───────────────────────────────────────────────

# Phase 1+2+3 combined CLI (with seccomp filter + capability drop)
# Requires: libseccomp-dev, libcap-dev
#   sudo apt install libseccomp-dev libcap-dev
$(BINDIR)/sentry_sandbox_v3: $(SANDBOX)/sentry_sandbox_v3.c $(SANDBOX)/cgroup.c $(SANDBOX)/seccomp_policy.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $^ -lseccomp $(LDFLAGS)

# ── Test helpers ──────────────────────────────────────────────────────

# Step 3.2: binary that deliberately calls a blocked syscall
$(BINDIR)/test_seccomp_block: $(TESTS)/samples/harmful/seccomp/test_seccomp_block.c | $(BINDIR)
	$(CC) -O0 -o $@ $< $(LDFLAGS)

# Stress tests
$(BINDIR)/stress_cpu: $(TESTS)/samples/harmful/resource-abuse/stress_cpu.c | $(BINDIR)
	$(CC) -O2 -o $@ $< $(LDFLAGS)

$(BINDIR)/stress_mem: $(TESTS)/samples/harmful/resource-abuse/stress_mem.c | $(BINDIR)
	$(CC) -O0 -o $@ $< $(LDFLAGS)

$(BINDIR)/stress_fork: $(TESTS)/samples/harmful/resource-abuse/stress_fork.c | $(BINDIR)
	$(CC) -O0 -o $@ $< $(LDFLAGS)

$(BINDIR)/stress_files: $(TESTS)/samples/harmful/resource-abuse/stress_files.c | $(BINDIR)
	$(CC) -O2 -o $@ $< $(LDFLAGS)

$(BINDIR)/stress_net: $(TESTS)/samples/harmful/resource-abuse/stress_net.c | $(BINDIR)
	$(CC) -O2 -o $@ $< $(LDFLAGS)

# ── Scan test binaries (t1-t5) ───────────────────────────────────────
$(BINDIR)/t1_clean: $(TESTS)/samples/safe/t1_clean.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BINDIR)/t2_file_drop: $(TESTS)/samples/harmful/behaviour/t2_file_drop.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BINDIR)/t3_secret_reader: $(TESTS)/samples/harmful/behaviour/t3_secret_reader.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BINDIR)/t4_network: $(TESTS)/samples/harmful/behaviour/t4_network.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BINDIR)/t5_spawner: $(TESTS)/samples/harmful/behaviour/t5_spawner.c | $(BINDIR)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# ── Escape test C sources (Part 3) ────────────────────────────────────

ESCAPE_SRC = $(TESTS)/escape_src
ESCAPE_BIN = $(BINDIR)/escape

$(ESCAPE_BIN):
	mkdir -p $(ESCAPE_BIN)

$(ESCAPE_BIN)/read_host_file: $(ESCAPE_SRC)/read_host_file.c | $(ESCAPE_BIN)
	$(CC) -O0 -o $@ $< $(LDFLAGS)

$(ESCAPE_BIN)/write_proc: $(ESCAPE_SRC)/write_proc.c | $(ESCAPE_BIN)
	$(CC) -O0 -o $@ $< $(LDFLAGS)

$(ESCAPE_BIN)/mknod_dev: $(ESCAPE_SRC)/mknod_dev.c | $(ESCAPE_BIN)
	$(CC) -O0 -o $@ $< $(LDFLAGS)

$(ESCAPE_BIN)/chroot_escape: $(ESCAPE_SRC)/chroot_escape.c | $(ESCAPE_BIN)
	$(CC) -O0 -o $@ $< $(LDFLAGS)

$(ESCAPE_BIN)/fork_bomb: $(ESCAPE_SRC)/fork_bomb.c | $(ESCAPE_BIN)
	$(CC) -O0 -o $@ $< $(LDFLAGS)

$(ESCAPE_BIN)/raw_socket: $(ESCAPE_SRC)/raw_socket.c | $(ESCAPE_BIN)
	$(CC) -O0 -o $@ $< $(LDFLAGS)

$(ESCAPE_BIN)/tiocsti_inject: $(ESCAPE_SRC)/tiocsti_inject.c | $(ESCAPE_BIN)
	$(CC) -O0 -o $@ $< $(LDFLAGS)

$(ESCAPE_BIN)/fd_leak: $(ESCAPE_SRC)/fd_leak.c | $(ESCAPE_BIN)
	$(CC) -O0 -o $@ $< $(LDFLAGS)

$(ESCAPE_BIN)/clone_newuser: $(ESCAPE_SRC)/clone_newuser.c | $(ESCAPE_BIN)
	$(CC) -O0 -o $@ $< $(LDFLAGS)

escape-binaries: $(ESCAPE_BIN)/read_host_file $(ESCAPE_BIN)/write_proc \
                 $(ESCAPE_BIN)/mknod_dev $(ESCAPE_BIN)/chroot_escape \
                 $(ESCAPE_BIN)/fork_bomb $(ESCAPE_BIN)/raw_socket \
                 $(ESCAPE_BIN)/tiocsti_inject $(ESCAPE_BIN)/fd_leak \
                 $(ESCAPE_BIN)/clone_newuser

# Run the escape test suite (requires sudo)
test: escape-test

escape-test: $(BINDIR)/sentry_sandbox_v3 escape-binaries
	sudo bash $(TESTS)/escape_tests.sh $(BINDIR) $(ESCAPE_BIN)

# ── Helpers ───────────────────────────────────────────────────────────

clean:
	rm -rf $(BINDIR)

# Prepare the sandbox root filesystem (requires sudo)
setup:
	sudo bash $(SANDBOX)/setup_sandbox_root.sh $(SANDBOX_ROOT)

# Copy test binaries into the sandbox root so they can be exec'd inside
install-tests: $(BINDIR)/stress_cpu $(BINDIR)/stress_mem $(BINDIR)/stress_fork $(BINDIR)/stress_files $(BINDIR)/stress_net $(BINDIR)/test_seccomp_block
	sudo cp $(BINDIR)/stress_cpu          $(SANDBOX_ROOT)/bin/stress_cpu
	sudo cp $(BINDIR)/stress_mem          $(SANDBOX_ROOT)/bin/stress_mem
	sudo cp $(BINDIR)/stress_fork         $(SANDBOX_ROOT)/bin/stress_fork
	sudo cp $(BINDIR)/stress_files        $(SANDBOX_ROOT)/bin/stress_files
	sudo cp $(BINDIR)/stress_net          $(SANDBOX_ROOT)/bin/stress_net
	sudo cp $(BINDIR)/test_seccomp_block  $(SANDBOX_ROOT)/bin/test_seccomp_block
	sudo chmod 755 $(SANDBOX_ROOT)/bin/stress_cpu         \
	               $(SANDBOX_ROOT)/bin/stress_mem          \
	               $(SANDBOX_ROOT)/bin/stress_fork         \
	               $(SANDBOX_ROOT)/bin/stress_files        \
	               $(SANDBOX_ROOT)/bin/stress_net          \
	               $(SANDBOX_ROOT)/bin/test_seccomp_block
	@echo "[install-tests] Test binaries installed to $(SANDBOX_ROOT)/bin/"

# ── Legacy phase test targets (regression) ────────────────────────────

test3:
	sudo bash $(TESTS)/test_phase3.sh $(BINDIR)

test4:
	sudo bash $(TESTS)/test_phase4.sh $(BINDIR)

test5:
	sudo bash $(TESTS)/test_phase5.sh $(BINDIR)

test6:
	sudo bash $(TESTS)/test_phase6.sh $(BINDIR)

test7:
	sudo bash $(TESTS)/test_phase7.sh $(BINDIR)

test8:
	sudo bash $(TESTS)/test_phase8.sh $(BINDIR)

test10:
	sudo bash $(TESTS)/test_phase10.sh $(BINDIR)

test11:
	sudo bash $(TESTS)/test_phase11.sh $(BINDIR)

test12:
	sudo bash $(TESTS)/test_phase12.sh $(BINDIR)

test13:
	sudo bash $(TESTS)/test_phase13.sh $(BINDIR)

# Run ALL phases end-to-end
test-all: escape-test test3 test4 test5 test6 test7 test8 test10 test11 test12 test13
	@echo ""
	@echo "╔═══════════════════════════════════════════════════════════════╗"
	@echo "║     ALL SENTRY TEST SUITES PASSED                             ║"
	@echo "╚═══════════════════════════════════════════════════════════════╝"

web:
	sudo python3 web/server.py

web-stub:
	SENTRY_SCAN_STUB=1 python3 web/server.py

demo:
	@if [ ! -f bin/sentry_sandbox_v3 ]; then $(MAKE); fi
	@if [ ! -d /opt/sentry/sandbox-root/opt/sample ]; then sudo $(MAKE) setup; fi
	@echo "Open http://localhost:8080"
	sudo python3 web/server.py

demo-stub:
	SENTRY_SCAN_STUB=1 python3 web/server.py
