"""
cpu_stress.py — Phase 11: Configurable Multi-Threaded CPU Stress Test

Burns CPU cycles across multiple worker threads to trigger SENTRY's
CPU_ANOMALY heuristic rule and cgroup CPU quota throttling.

Usage:
    python3 tests/cpu_stress.py [--duration 3.0] [--threads 2]
"""

import sys
import time
import argparse
import threading


def burn_cpu(duration: float, stop_event: threading.Event):
    start = time.time()
    x = 0
    while not stop_event.is_set() and (time.time() - start) < duration:
        x = (x + 1) % 1000000


def main():
    parser = argparse.ArgumentParser(description="SENTRY CPU Stress Generator")
    parser.add_argument("--duration", type=float, default=3.0, help="Duration to burn CPU in seconds")
    parser.add_argument("--threads", type=int, default=2, help="Number of concurrent worker threads")
    args = parser.parse_args()

    print(f"[cpu_stress] Starting CPU burn: {args.threads} threads for {args.duration}s...")
    stop_event = threading.Event()
    threads = []

    start = time.time()
    for i in range(args.threads):
        t = threading.Thread(target=burn_cpu, args=(args.duration, stop_event), daemon=True)
        t.start()
        threads.append(t)

    for t in threads:
        t.join(timeout=args.duration + 2.0)

    elapsed = time.time() - start
    print(f"[cpu_stress] Completed CPU burn in {elapsed:.2f}s.")


if __name__ == "__main__":
    main()
