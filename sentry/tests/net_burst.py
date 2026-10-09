#!/usr/bin/env python3
"""
net_burst.py — Phase 11: Network Connection Burst Stress Test

Attempts rapid outbound TCP connections to test SENTRY's NetworkMonitor
(Phase 6) and outbound network burst rule (rule_network_burst).
Connections may fail (e.g. in an isolated network namespace), but the
connection attempts will register in /proc/net/tcp.

Usage:
    python3 tests/net_burst.py [--count 40] [--interval 0.05]
"""

import sys
import time
import socket
import argparse


def main():
    parser = argparse.ArgumentParser(description="SENTRY Network Connection Burst Generator")
    parser.add_argument("--count", type=int, default=40, help="Number of connection attempts to generate")
    parser.add_argument("--interval", type=float, default=0.05, help="Delay between connection attempts in seconds")
    parser.add_argument("--hold-time", type=float, default=2.0, help="Time to hold open sockets in seconds")
    args = parser.parse_args()

    targets = [
        ("1.1.1.1", 80),
        ("8.8.8.8", 53),
        ("9.9.9.9", 443),
        ("10.255.255.1", 8080),
        ("192.0.2.1", 80),
        ("198.51.100.1", 443),
        ("203.0.113.1", 80)
    ]

    print(f"[net_burst] Initiating {args.count} outbound connection attempts (interval: {args.interval}s)...")
    sockets = []
    attempted = 0
    start = time.time()

    for i in range(args.count):
        ip, port = targets[i % len(targets)]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setblocking(False)
        try:
            s.connect_ex((ip, port))
        except Exception:
            pass
        sockets.append(s)
        attempted += 1

        if (i + 1) % 10 == 0 or (i + 1) == args.count:
            print(f"[net_burst] Attempted {attempted}/{args.count} connections...")

        if args.interval > 0:
            time.sleep(args.interval)

    elapsed = time.time() - start
    print(f"[net_burst] Holding {len(sockets)} sockets open for {args.hold_time}s...")
    time.sleep(args.hold_time)

    for s in sockets:
        try:
            s.close()
        except Exception:
            pass

    total_time = time.time() - start
    rate_min = (attempted / max(total_time, 0.001)) * 60.0
    print(f"[net_burst] Completed {attempted} attempts in {total_time:.2f}s ({rate_min:.1f} attempts/min).")


if __name__ == "__main__":
    main()
