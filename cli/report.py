"""
report.py -- Build a compact summary dict from a finished scan's SQLite DB.

Usage:
    from cli.report import build_report
    report = build_report(db_path)   # db_path is the path to scan.db
"""

import json
import os
import sqlite3
import time
from typing import Any, Dict, List


_SENSITIVE_PATTERNS = (
    "/etc/shadow", "/etc/passwd", "/etc/sudoers",
    "/.ssh/", "/id_rsa", "/authorized_keys",
    "/proc/", "/sys/", "/root/",
)

_CAP = 6000  # soft JSON character cap


def _cap_list(items: List[str], n: int = 5) -> List[str]:
    return items[:n]


def _verdict_for(score: int) -> str:
    if score >= 61:
        return "MALICIOUS"
    if score >= 21:
        return "SUSPICIOUS"
    return "SAFE"


def build_report(db_path: str) -> Dict[str, Any]:
    """Read the SQLite log at *db_path* and return a compact report dict.

    Keys:
        verdict             – SAFE / SUSPICIOUS / MALICIOUS
        score               – peak risk score (0-100)
        coverage            – dict of monitor coverage statuses
        files_written       – {count, examples}
        network_attempts    – {count, examples}
        processes_spawned   – {count, examples}
    """
    report: Dict[str, Any] = {
        "verdict": "SAFE",
        "score": 0,
        "coverage": {
            "files_written": "observed",
            "network": "not_monitored",
            "file_reads": "not_monitored",
            "processes": "sampled",
        },
        "files_written": {"count": 0, "examples": []},
        "network_attempts": {"count": 0, "examples": []},
        "processes_spawned": {"count": 0, "examples": []},
    }

    if not os.path.exists(db_path):
        return report

    try:
        con = sqlite3.connect(db_path)
        con.row_factory = sqlite3.Row
        try:
            # Peak risk score
            row = con.execute(
                "SELECT MAX(score) as ms FROM risk_scores"
            ).fetchone()
            if row and row["ms"] is not None:
                report["score"] = int(row["ms"])

            # Files written matching monitor/file_monitor.py events
            write_rows = con.execute(
                "SELECT path FROM file_events WHERE event_type IN ('CREATE','MODIFY','MOVED_TO') ORDER BY id"
            ).fetchall()
            write_paths = [r["path"] for r in write_rows]
            report["files_written"]["count"] = len(write_paths)
            report["files_written"]["examples"] = _cap_list(write_paths)

            # Network attempts – from network_samples destinations
            dest_set: List[str] = []
            total_conns = 0
            for ns in con.execute(
                "SELECT active_connections, connection_rate, destinations FROM network_samples ORDER BY id"
            ).fetchall():
                total_conns = max(total_conns, int(ns["active_connections"]))
                try:
                    dests = json.loads(ns["destinations"] or "[]")
                    for d in dests:
                        if d and d not in dest_set:
                            dest_set.append(d)
                except (ValueError, TypeError):
                    pass
            # count = total unique destination strings seen, or max active_connections
            net_count = max(total_conns, len(dest_set))
            report["network_attempts"]["count"] = net_count
            report["network_attempts"]["examples"] = _cap_list(dest_set)

            # Processes spawned – peak child_count from process_samples
            proc_row = con.execute(
                "SELECT MAX(child_count) as mc, MAX(spawn_rate) as mr FROM process_samples"
            ).fetchone()
            if proc_row:
                max_children = int(proc_row["mc"] or 0)
                report["processes_spawned"]["count"] = max_children
                # examples: grab distinct child PIDs if stored, else just note the count
                spawn_rows = con.execute(
                    "SELECT DISTINCT child_count FROM process_samples WHERE child_count > 0 ORDER BY child_count DESC LIMIT 5"
                ).fetchall()
                report["processes_spawned"]["examples"] = [
                    f"{r['child_count']} concurrent children" for r in spawn_rows
                ]
        finally:
            con.close()
    except Exception:
        pass

    report["verdict"] = _verdict_for(report["score"])

    # Trim to ~6000 chars
    txt = json.dumps(report)
    if len(txt) > _CAP:
        for cat in ("files_written", "network_attempts", "processes_spawned"):
            ex = report[cat]["examples"]
            while len(json.dumps(report)) > _CAP and ex:
                ex.pop()

    return report

