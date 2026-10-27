#!/usr/bin/env python3
"""
process_storm.py — Phase 11: Process Storm / Fork-Bomb-Lite Stress Test

Spawns child processes in a loop with a hard internal safety cap
(max 100 processes) to test SENTRY's fork bomb detection rule
(rule_fork_bomb) and cgroup pids.max enforcement.

Usage:
    python3 tests/process_storm.py [--max-procs 50] [--hold-time 3.0] [--interval 0.05]
"""

import os
import sys
import time
import argparse
import multiprocessing


def child_worker(hold_time: float):
    """Child process workload: sleeps to maintain active process count."""
    try:
        time.sleep(hold_time)
    except KeyboardInterrupt:
        pass


def main():
    parser = argparse.ArgumentParser(description="SENTRY Process Storm Generator")
    parser.add_argument("--max-procs", type=int, default=50, help="Number of child processes to spawn (safety cap: 100)")
    parser.add_argument("--hold-time", type=float, default=3.0, help="How long children stay alive in seconds")
    parser.add_argument("--interval", type=float, default=0.05, help="Delay between spawn attempts in seconds")
    args = parser.parse_args()

    # Hard internal safety cap
    effective_max = min(max(args.max_procs, 1), 100)
    print(f"[process_storm] Spawning up to {effective_max} child processes (safety cap: 100, hold: {args.hold_time}s)...")

    children = []
    spawn_errors = 0
    start = time.time()

    for i in range(effective_max):
        try:
            p = multiprocessing.Process(target=child_worker, args=(args.hold_time,), daemon=False)
            p.start()
            children.append(p)
            if (i + 1) % 10 == 0 or (i + 1) == effective_max:
                print(f"[process_storm] Spawned {len(children)} processes...")
        except (BlockingIOError, OSError) as e:
            # Reached cgroup pids.max or system process limit
            spawn_errors += 1
            print(f"[process_storm] Spawn blocked by OS / cgroup after {len(children)} processes: {e}")
            break

        if args.interval > 0:
            time.sleep(args.interval)

    print(f"[process_storm] Active children: {len(children)}. Holding for {args.hold_time}s...")
    for p in children:
        p.join(timeout=args.hold_time + 2.0)

    elapsed = time.time() - start
    print(f"[process_storm] Completed process storm: {len(children)} spawned, {spawn_errors} blocked in {elapsed:.2f}s.")


if __name__ == "__main__":
    main()
