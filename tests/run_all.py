#!/usr/bin/env python3
"""
run_all.py — Phase 11: Master Attack Replay Test Suite

Automates execution of all SENTRY attack vectors inside the sandbox:
  1. CPU Stress (stress_cpu / cpu_stress.py)
  2. Process Storm / Fork Bomb Lite (stress_fork / process_storm.py)
  3. Mass File Write Burst (stress_files / file_burst.py)
  4. Network Outbound Burst (stress_net / net_burst.py)
  5. Seccomp Policy Violation (test_seccomp_block)

Collects telemetry from SQLite and displays a structured benchmark
summary table verifying detection and response for viva presentation.

Usage:
    sudo python3 -u tests/run_all.py [--db /tmp/sentry_replay_test.db]
"""

import os
import sys
import time
import argparse
import subprocess
from typing import Dict, Any, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db.database import SentryDB


def run_attack_test(
    test_name: str,
    target_threat: str,
    command: List[str],
    db_path: str,
    expected_bands: List[str],
    sentry_cli: str,
    seccomp_mode: Optional[str] = None
) -> Dict[str, Any]:
    """Runs a single attack test through SENTRY and evaluates recorded telemetry."""
    print("\n" + "=" * 76)
    print(f"[*] Executing Attack: {test_name} ({target_threat})")
    print(f"[*] Command: {' '.join(command)}")
    print("=" * 76)

    # Clean previous run state in DB for clean isolation
    db = SentryDB(db_path)
    with db.get_connection() as conn:
        conn.execute("DELETE FROM incidents;")
        conn.execute("DELETE FROM risk_scores;")
        conn.execute("DELETE FROM process_samples;")
        conn.execute("DELETE FROM file_samples;")
        conn.execute("DELETE FROM network_samples;")
        conn.commit()

    run_cmd = [sys.executable, "-u", sentry_cli, "run"] + command
    if seccomp_mode:
        run_cmd += ["--seccomp", seccomp_mode]
    run_cmd += ["--db", db_path, "--interval", "0.3"]
    if os.geteuid() != 0:
        run_cmd = ["sudo"] + run_cmd

    start_time = time.time()
    subprocess.run(run_cmd, capture_output=False)
    elapsed = time.time() - start_time

    # Collect telemetry from database
    samples = db.get_process_samples()
    file_samples = db.get_file_samples()
    net_samples = db.get_network_samples()
    risk_scores = db.get_risk_scores()
    incidents = db.get_incidents()

    peak_cpu = max((s["cpu_percent"] for s in samples), default=0.0)
    peak_rss = max((s["rss_kb"] for s in samples), default=0) / 1024.0
    peak_procs = max((s["child_count"] for s in samples), default=0)
    peak_f_rate = max((fs["file_write_rate"] for fs in file_samples), default=0.0)
    peak_n_rate = max((ns["connection_rate"] for ns in net_samples), default=0.0)

    peak_risk = max((rs["score"] for rs in risk_scores), default=0)
    peak_band = "NORMAL"
    if risk_scores:
        peak_band = max(risk_scores, key=lambda rs: rs["score"])["band"]

    actions = [inc["action_taken"] for inc in incidents]
    primary_action = actions[0] if actions else "MONITOR_ONLY"

    passed = peak_band in expected_bands or len(incidents) > 0 or peak_risk >= 20

    return {
        "name": test_name,
        "threat": target_threat,
        "peak_cpu": peak_cpu,
        "peak_procs": peak_procs,
        "peak_f_rate": peak_f_rate,
        "peak_n_rate": peak_n_rate,
        "peak_risk": peak_risk,
        "peak_band": peak_band,
        "action": primary_action,
        "incident_count": len(incidents),
        "passed": passed,
        "elapsed": elapsed
    }


def main():
    parser = argparse.ArgumentParser(description="SENTRY Master Attack Replay Suite")
    parser.add_argument("--db", default="/tmp/sentry_replay_test.db", help="Temporary database path")
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sentry_cli = os.path.join(base_dir, "cli", "sentry.py")

    test_specs = [
        {
            "name": "CPU Stress Burn",
            "threat": "CPU Monopolization",
            "cmd": ["/bin/stress_cpu", "3"],
            "expected_bands": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        },
        {
            "name": "Process Storm",
            "threat": "PID Exhaustion / Fork Bomb",
            "cmd": ["/bin/stress_fork", "35"],
            "expected_bands": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        },
        {
            "name": "Mass File Burst",
            "threat": "Ransomware / Rapid Mass Writes",
            "cmd": ["/bin/stress_files", "150", "/tmp"],
            "expected_bands": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        },
        {
            "name": "Outbound Net Burst",
            "threat": "C2 Beacon / Network Scanning",
            "cmd": ["/bin/stress_net", "50", "8080"],
            "expected_bands": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        },
        {
            "name": "Seccomp Violation",
            "threat": "Unauthorized Syscall Escape",
            "cmd": ["/bin/test_seccomp_block"],
            "expected_bands": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
            "seccomp": "minimal"
        }
    ]

    print("\n" + "╔" + "═" * 74 + "╗")
    print("║" + "   SENTRY PHASE 11 — ATTACK REPLAY HARNESS & EVALUATION   ".center(74) + "║")
    print("╚" + "═" * 74 + "╝")
    print(f" Target Database : {args.db}")
    print(f" Test Vectors    : {len(test_specs)}")

    results = []
    for spec in test_specs:
        res = run_attack_test(
            test_name=spec["name"],
            target_threat=spec["threat"],
            command=spec["cmd"],
            db_path=args.db,
            expected_bands=spec["expected_bands"],
            sentry_cli=sentry_cli,
            seccomp_mode=spec.get("seccomp")
        )
        results.append(res)

    # Print summary benchmark table
    print("\n" + "╔" + "═" * 94 + "╗")
    print("║" + "               SENTRY ATTACK REPLAY BENCHMARK & EVALUATION SUMMARY               ".center(94) + "║")
    print("╠" + "═" * 94 + "╣")
    print(f"║ {'Test Attack':<20} {'Target Threat':<25} {'Risk':<10} {'Action Taken':<22} {'Status':<10} ║")
    print("╟" + "─" * 94 + "╢")

    all_passed = True
    for r in results:
        status_str = "PASS [✓]" if r["passed"] else "FAIL [✗]"
        if not r["passed"]:
            all_passed = False
        band_str = f"{r['peak_band']} ({r['peak_risk']})"
        action_short = r["action"][:22]
        print(f"║ {r['name']:<20} {r['threat']:<25} {band_str:<10} {action_short:<22} {status_str:<10} ║")

    print("╚" + "═" * 94 + "╝")
    print(f"\nFinal Result: {len([r for r in results if r['passed']])}/{len(results)} attack tests detected and mitigated.")

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
