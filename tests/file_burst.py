#!/usr/bin/env python3
"""
file_burst.py — Phase 11: Mass File-Write Stress Test

Generates rapid file creation and write bursts at a configurable rate
to test SENTRY's FileMonitor (Phase 5) and mass file-write heuristic
rule (rule_mass_file_writes).

Usage:
    python3 tests/file_burst.py [--target-dir /tmp/sentry_burst] [--count 120] [--rate 50]
"""

import os
import sys
import time
import shutil
import argparse


def main():
    parser = argparse.ArgumentParser(description="SENTRY Mass File-Write Generator")
    parser.add_argument("--target-dir", default="/tmp/sentry_file_burst", help="Directory where files will be written")
    parser.add_argument("--count", type=int, default=120, help="Total number of files to write")
    parser.add_argument("--rate", type=float, default=50.0, help="Target writes per second (0 for max speed)")
    parser.add_argument("--size", type=int, default=64, help="Size in bytes of each file written")
    parser.add_argument("--keep", action="store_true", help="Keep files instead of cleaning up on exit")
    args = parser.parse_args()

    os.makedirs(args.target_dir, exist_ok=True)
    payload = b"SENTRY_TEST_PAYLOAD_" + b"X" * max(0, args.size - 20)

    delay = 1.0 / args.rate if args.rate > 0 else 0.0
    print(f"[file_burst] Writing {args.count} files into '{args.target_dir}' at target rate {args.rate:.1f} files/s...")

    start = time.time()
    written = 0

    try:
        for i in range(args.count):
            filepath = os.path.join(args.target_dir, f"burst_{os.getpid()}_{i:05d}.tmp")
            with open(filepath, "wb") as f:
                f.write(payload)
                f.flush()
            written += 1
            if (i + 1) % 25 == 0 or (i + 1) == args.count:
                print(f"[file_burst] Written {written}/{args.count} files...")
            if delay > 0:
                time.sleep(delay)
    finally:
        elapsed = time.time() - start
        effective_rate_sec = written / max(elapsed, 0.001)
        effective_rate_min = effective_rate_sec * 60.0
        print(f"[file_burst] Finished: {written} files written in {elapsed:.2f}s ({effective_rate_min:.1f} files/min).")

        if not args.keep:
            try:
                shutil.rmtree(args.target_dir, ignore_errors=True)
                print(f"[file_burst] Cleaned up temporary directory '{args.target_dir}'.")
            except Exception as e:
                print(f"[file_burst] Warning: cleanup failed: {e}")


if __name__ == "__main__":
    main()
