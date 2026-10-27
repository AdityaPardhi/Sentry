"""
incidents_report.py — Formal Incident & Forensic Report Generator

Produces printable digital forensic incident reports from SQLite:
  - Reads consolidated incident schema from the database.
  - Displays full lifecycle from detection to resolution.
  - Outputs boxed incident cards, compact terminal tables, or JSON.

Usage:
    python3 db/incidents_report.py [--db sentry.db] [--format boxed|table|json]
"""

import os
import sys
import json
import argparse
from typing import List, Dict, Any

# Ensure import of SentryDB
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db.database import SentryDB


def render_boxed_card(inc: Dict[str, Any]) -> str:
    """Renders a single incident as a clean ASCII boxed forensic card."""
    inc_id = inc.get("incident_id") or inc.get("id", 1)
    exe = inc.get("executable", "unknown")
    pid = inc.get("pid", 0)
    det_time = inc.get("detection_time", "unknown")
    cpu = inc.get("cpu_percent", 0.0)
    rss_mb = (inc.get("rss_kb", 0)) / 1024.0
    files_rate = inc.get("file_write_rate", 0.0)
    conns = inc.get("connection_attempts", 0)
    score = inc.get("risk_score") or inc.get("score", 0)
    band = inc.get("risk_band") or inc.get("band", "UNKNOWN")
    action = inc.get("action_taken", "NONE")
    resolution = inc.get("resolution", "PENDING")
    details = inc.get("details", "")

    width = 78
    bar = "═" * width
    div = "─" * width

    lines = [
        f"╔{bar}╗",
        f"║  SENTRY DIGITAL FORENSICS INCIDENT REPORT — RECORD #{inc_id:<22} ║",
        f"╠{bar}╣",
        f"║  Target Process     : {exe} (PID: {pid})".ljust(width + 1) + "║",
        f"║  Detection Timestamp: {det_time}".ljust(width + 1) + "║",
        f"╟{div}╢",
        f"║  Observed Telemetry Breakdown:".ljust(width + 1) + "║",
        f"║    • CPU Utilization : {cpu:5.1f}%".ljust(width + 1) + "║",
        f"║    • RSS Memory      : {rss_mb:5.2f} MB".ljust(width + 1) + "║",
        f"║    • File I/O Rate   : {files_rate:5.1f} files/min".ljust(width + 1) + "║",
        f"║    • Network Attempts: {conns} connection attempts".ljust(width + 1) + "║",
        f"╟{div}╢",
        f"║  Security Evaluation : Score: {score}/100  [Band: {band}]".ljust(width + 1) + "║",
        f"║  Mitigation Action   : {action}".ljust(width + 1) + "║",
        f"║  Incident Resolution : {resolution}".ljust(width + 1) + "║",
    ]

    if details:
        lines.append(f"║  Forensic Notes      : {details[:width - 25]}".ljust(width + 1) + "║")

    lines.append(f"╚{bar}╝")
    return "\n".join(lines)


def dump_table(incidents: List[Dict[str, Any]]) -> None:
    """Prints a concise aligned table of incidents."""
    if not incidents:
        print("No incident records found.")
        return

    print("=" * 86)
    print(" SENTRY CONSOLIDATED INCIDENT TABLE (Phase 10)")
    print("=" * 86)
    print(f"{'ID':<4} {'PID':<6} {'Executable':<18} {'Time':<19} {'Score':<6} {'Band':<8} {'Resolution':<10} {'Action'}")
    print("─" * 86)
    for inc in incidents:
        inc_id = inc.get("incident_id") or inc.get("id", 1)
        pid = inc.get("pid", 0)
        exe = os.path.basename(inc.get("executable", "unknown"))
        t_str = inc.get("detection_time", "")[-19:]
        score = inc.get("risk_score") or inc.get("score", 0)
        band = inc.get("risk_band") or inc.get("band", "UNKNOWN")
        res = inc.get("resolution", "PENDING")
        action = inc.get("action_taken", "")
        print(f"{inc_id:<4} {pid:<6} {exe:<18} {t_str:<19} {score:<6} {band:<8} {res:<10} {action}")
    print("=" * 86)


def main():
    parser = argparse.ArgumentParser(
        description="SENTRY Forensic Incident Report Generator (Phase 10)",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--db", default="sentry.db", help="SQLite database path (default: sentry.db)")
    parser.add_argument("--format", choices=["boxed", "table", "json"], default="boxed",
                        help="Output format: boxed (default), table, json")
    parser.add_argument("--pid", type=int, default=None, help="Filter by process PID")
    parser.add_argument("--limit", type=int, default=50, help="Max records to display (default: 50)")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"Error: Database '{args.db}' not found.", file=sys.stderr)
        sys.exit(1)

    db = SentryDB(args.db)
    incidents = db.get_incidents(pid=args.pid, limit=args.limit)

    if not incidents:
        print(f"No incident records found in '{args.db}'.")
        return

    if args.format == "boxed":
        for inc in incidents:
            print(render_boxed_card(inc))
            print("")
    elif args.format == "table":
        dump_table(incidents)
    elif args.format == "json":
        print(json.dumps(incidents, indent=2))


if __name__ == "__main__":
    main()
