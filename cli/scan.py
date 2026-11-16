#!/usr/bin/env python3
"""
scan.py -- one-command safety check for a downloaded file.

    sudo python3 cli/scan.py ~/Downloads/installer.sh
    sudo python3 cli/scan.py demo/fake_dropper.sh --json

Stages
  1. Static checks  (SHA-256, file type, suspicious text patterns). The file is NOT run.
  2. Sandbox run    (the normal `sentry.py run`, with live monitoring), when the file is a
                    script or program the sandbox can run.
  3. Verdict        (static points + highest behaviour risk score seen during the run).

Exit codes: 0 no issues observed, 1 suspicious, 2 malicious,
            3 could not scan, 4 only partly checked (e.g. could not be run).

With --json, exactly one JSON object is printed on stdout; all human text goes to stderr.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
try:
    from cli.report import build_report
except ImportError:
    from report import build_report

SANDBOX_ROOT = os.environ.get("SENTRY_ROOT", "/opt/sentry/sandbox-root")
SAMPLE_DIR = "opt/sample"          # must already exist (setup_sandbox_root.sh creates it)
LOG_TAIL = 4000

# (regex, points, reason): cheap text heuristics, run on the first 2 MB of the file.
STATIC_RULES = [
    (rb"curl[^\n]*\|\s*(ba)?sh|wget[^\n]*\|\s*(ba)?sh", 25, "pipes a download straight into a shell"),
    (rb"/etc/shadow", 20, "references the system password-hash file"),
    (rb"\.ssh/|id_rsa|authorized_keys", 25, "touches SSH keys"),
    (rb"crontab|/etc/cron|\.bashrc|\.profile|systemctl\s+enable|rc\.local", 20,
     "tries to persist across reboots"),
    (rb"base64\s+(-d|--decode)", 15, "decodes hidden payloads"),
    (rb"nc\s+-e|/dev/tcp/|bash\s+-i", 35, "opens a reverse shell"),
    (rb"rm\s+-rf\s+(/|~|\$HOME)(\s|$)", 30, "deletes large parts of the system"),
    (rb"xmrig|stratum\+tcp|cryptonight", 40, "looks like a crypto-miner"),
    (rb"chmod\s+(\+x|[0-7]*7[0-7]*)\s", 5, "changes file permissions"),
]

SHELLS = {"sh", "bash", "dash"}


def _categorize(finding):
    src = str(finding.get("source", "")).lower()
    rule = str(finding.get("rule", "")).lower()
    reason = str(finding.get("reason", "")).lower()
    if src == "static":
        return "static"
    if "seccomp" in rule or "sigsys" in rule or "syscall" in rule or "seccomp" in reason or "sigsys" in reason:
        return "seccomp"
    if any(k in rule or k in reason for k in ("file", "write", "creat", "modif", "delete")):
        return "file"
    if any(k in rule or k in reason for k in ("proc", "cpu", "fork", "spawn", "burst", "pid", "memory", "rss")):
        return "process"
    return "process"


def log(msg, quiet_json):
    print(msg, file=sys.stderr if quiet_json else sys.stdout)


def sha256_of(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def detect_type(path):
    """Return (kind, interpreter). kind: elf | script | pe | other."""
    with open(path, "rb") as f:
        head = f.read(256)
    if head.startswith(b"\x7fELF"):
        return "elf", None
    if head.startswith(b"MZ"):
        return "pe", None
    if head.startswith(b"#!"):
        line = head.split(b"\n", 1)[0][2:].decode(errors="ignore").strip().split()
        if line:
            name = os.path.basename(line[0])
            if name == "env" and len(line) > 1:
                name = os.path.basename(line[1])
            return "script", name
    lower_path = path.lower()
    if lower_path.endswith((".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".rs", ".go", ".java")):
        return "source", None
    if path.endswith(".py"):
        return "script", "python3"
    if path.endswith(".sh"):
        return "script", "sh"
    return "other", None


def static_scan(path):
    with open(path, "rb") as f:
        data = f.read(2 << 20)
    findings = []
    for pattern, points, reason in STATIC_RULES:
        if re.search(pattern, data, re.IGNORECASE):
            findings.append({"source": "static", "category": "static", "rule": "STATIC_PATTERN",
                             "points": points, "reason": reason})
    return findings


def interpreter_path(interp):
    """Path of the interpreter inside the sandbox root, or None if it is not installed there."""
    for d in ("bin", "usr/bin"):
        if os.path.isfile(os.path.join(SANDBOX_ROOT, d, interp)):
            return "/" + d + "/" + interp
    return None


def collect_dynamic(db_path, started):
    """Read one run's telemetry. Returns (score, findings, timeline, actions)."""
    score, findings, timeline, actions = 0, [], [], []
    if not os.path.exists(db_path):
        return score, findings, timeline, actions
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        rows = con.execute(
            "SELECT timestamp, cpu_percent, rss_kb, child_count FROM process_samples "
            "ORDER BY id").fetchall()
        if rows:
            t0 = rows[0]["timestamp"]
            for r in rows:
                timeline.append({"t": round(r["timestamp"] - t0, 2),
                                 "cpu_percent": round(r["cpu_percent"], 1),
                                 "rss_mb": round(r["rss_kb"] / 1024.0, 2),
                                 "processes": r["child_count"]})
        best = {}
        for r in con.execute("SELECT score, triggered_rules FROM risk_scores ORDER BY id"):
            score = max(score, int(r["score"]))
            try:
                rules = json.loads(r["triggered_rules"] or "[]")
            except ValueError:
                rules = []
            for rule in rules:
                name = rule.get("rule_name", "UNKNOWN")
                if name not in best or rule.get("points", 0) > best[name]["points"]:
                    cat = "process"
                    name_l = name.lower()
                    if "seccomp" in name_l or "syscall" in name_l:
                        cat = "seccomp"
                    elif "file" in name_l or "write" in name_l:
                        cat = "file"
                    best[name] = {"source": "dynamic", "category": cat, "rule": name,
                                  "points": int(rule.get("points", 0)),
                                  "reason": rule.get("reason", "")}
        findings = list(best.values())
        for r in con.execute("SELECT DISTINCT action_taken FROM incidents"):
            actions.append(r["action_taken"])
    finally:
        con.close()
    return score, findings, timeline, actions


AF_NAMES = {2: "AF_INET", 10: "AF_INET6", 16: "AF_NETLINK", 17: "AF_PACKET"}
SOCK_NAMES = {1: "stream/TCP", 2: "datagram/UDP", 3: "raw"}


def read_events(path):
    """Read the supervisor's JSON-lines log. Returns (events, file_existed)."""
    events = []
    if not os.path.exists(path):
        return events, False
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if isinstance(ev, dict):
                events.append(ev)
    return events, True


def events_to_findings(events):
    """Return (points, findings, network_examples, sensitive_path_examples)."""
    net = [e for e in events if e.get("type") == "network"]
    opens = [e for e in events if e.get("type") == "sensitive_open"]
    findings, net_ex, path_ex, points = [], [], [], 0
    if net:
        for e in net:
            fam = AF_NAMES.get(e.get("family"), "family %s" % e.get("family"))
            typ = SOCK_NAMES.get(e.get("sock_type"), "socket")
            ex = "%s %s socket" % (fam, typ)
            if ex not in net_ex:
                net_ex.append(ex)
        findings.append({"source": "dynamic", "category": "seccomp", "rule": "NETWORK_ATTEMPT",
                         "points": 30,
                         "reason": "Tried to open a network connection (%d attempt(s), blocked): %s"
                                   % (len(net), ", ".join(net_ex[:3]))})
        points += 30
    if opens:
        path_ex = sorted({str(e.get("path", "")) for e in opens})[:5]
        findings.append({"source": "dynamic", "category": "file", "rule": "SENSITIVE_FILE_READ",
                         "points": 25,
                         "reason": "Tried to open credential files: " + ", ".join(path_ex)})
        points += 25
    return points, findings, net_ex, path_ex


def run_in_sandbox(path, kind, interp, args, quiet_json, notes):
    """Copy the sample into the sandbox root, run it, return (ran, score, findings, timeline, log, behavior, exit_code, killed_by_signal)."""
    if kind == "script":
        ipath = interpreter_path(interp if interp not in SHELLS else interp)
        if ipath is None and interp in SHELLS:
            ipath = interpreter_path("sh")
        if ipath is None:
            notes.append(f"'{interp}' is not installed inside the sandbox root, so the script was "
                         f"not run. Only static checks were done.")
            return False, 0, [], [], "", None, None, None
    if not os.path.isdir(os.path.join(SANDBOX_ROOT, SAMPLE_DIR)):
        notes.append(f"{SANDBOX_ROOT}/{SAMPLE_DIR} does not exist. Run `sudo make setup`.")
        return False, 0, [], [], "", None, None, None

    name = "s_" + secrets.token_hex(6)
    dest = os.path.join(SANDBOX_ROOT, SAMPLE_DIR, name)
    inside = "/" + SAMPLE_DIR + "/" + name
    tmp = tempfile.mkdtemp(prefix="sentry_scan_")
    db_path = os.path.join(tmp, "scan.db")
    events_path = os.path.join(tmp, "events.jsonl")
    cmd = [inside] if kind == "elf" else [ipath, inside]
    run = [sys.executable, "-u", os.path.join(ROOT, "cli", "sentry.py"), "run", *cmd,
           "--profile", args.profile, "--seccomp", args.seccomp, "--db", db_path,
           "--events-file", events_path,
           "--interval", "0.5", "--timeout", str(args.timeout)]
    out = ""
    proc = None
    started = time.time()
    try:
        shutil.copyfile(path, dest)
        os.chmod(dest, 0o755)
        log(f"[scan] running in sandbox ({args.profile} profile, seccomp={args.seccomp}, "
            f"{args.timeout:.0f}s limit)...", quiet_json)
        try:
            proc = subprocess.run(run, capture_output=True, text=True, timeout=args.timeout + 25)
            out = (proc.stdout or "") + (proc.stderr or "")
        except subprocess.TimeoutExpired as e:
            out = (e.stdout or "") if isinstance(e.stdout, str) else ""
            notes.append("The scan helper did not finish in time and was stopped.")
    finally:
        try:
            os.remove(dest)
        except OSError:
            pass

    killed_by_signal = None
    exit_code = None
    if "SIGSYS" in out:
        killed_by_signal = "SIGSYS"
    elif "timed out" in out:
        killed_by_signal = "timed out"
    else:
        m = re.search(r"exit (?:code|status)[:\s]+(\d+)", out, re.IGNORECASE)
        if m:
            exit_code = int(m.group(1))
        elif proc is not None:
            exit_code = proc.returncode

    ran = "SENTRY SANDBOX" in out and "[sandbox] FATAL" not in out
    if not ran:
        notes.append("The sandbox did not start. Check that `make` and `sudo make setup` were run.")
    score, findings, timeline, actions = collect_dynamic(db_path, started)
    events, events_ok = read_events(events_path)
    ev_points, ev_findings, net_ex, path_ex = events_to_findings(events)
    findings.extend(ev_findings)
    score = min(score + ev_points, 100)
    if killed_by_signal == "SIGSYS":
        notes.append("The program was killed for trying a restricted system call. That is "
                     "suspicious, but it can also mean a harmless program needs a call Sentry "
                     "does not allow yet.")
        if not any(f.get("category") == "seccomp" or "seccomp" in f.get("rule", "").lower() for f in findings):
            findings.append({"source": "dynamic", "category": "seccomp", "rule": "SECCOMP_SIGSYS",
                             "points": 25, "reason": "Restricted system call blocked by seccomp policy (SIGSYS)"})
    if killed_by_signal == "timed out":
        notes.append("The program was still running at the time limit and was stopped.")
    for a in actions:
        findings.append({"source": "dynamic", "category": "process", "rule": "RESPONSE", "points": 0,
                         "reason": f"Sentry responded automatically: {a}"})

    behavior = build_report(db_path)
    if behavior is not None and events_ok:
        cov = behavior.setdefault("coverage", {})
        cov["network"] = "observed"
        cov["file_reads"] = "credential_paths_only"
        behavior["network_attempts"] = {"count": sum(1 for e in events if e.get("type") == "network"), "examples": net_ex}
        behavior["files_read_sensitive"] = {"count": sum(1 for e in events if e.get("type") == "sensitive_open"), "examples": path_ex}
    if args.keep_db:
        notes.append(f"Telemetry kept at {db_path}")
    else:
        shutil.rmtree(tmp, ignore_errors=True)
    return ran, score, findings, timeline, out[-LOG_TAIL:], behavior, exit_code, killed_by_signal


def verdict_for(total, fully_checked):
    if total >= 61:
        return "MALICIOUS", 2
    if total >= 21:
        return "SUSPICIOUS", 1
    if not fully_checked:
        return "NOT FULLY CHECKED", 4
    return "NO ISSUES OBSERVED", 0


def main():
    ap = argparse.ArgumentParser(description="SENTRY one-command file scan")
    ap.add_argument("file")
    ap.add_argument("--timeout", type=float, default=20.0)
    ap.add_argument("--profile", default="normal", choices=["strict", "normal", "development"])
    ap.add_argument("--seccomp", default="standard", choices=["minimal", "standard", "permissive"])
    ap.add_argument("--json", action="store_true", help="print one JSON object on stdout")
    ap.add_argument("--keep-db", action="store_true")
    ap.add_argument("--static-only", action="store_true", help="never run the file")
    args = ap.parse_args()
    q = args.json
    started = time.time()

    result = {"file_name": os.path.basename(args.file), "sha256": None, "file_type": None,
              "size_bytes": 0, "exit_code": None, "killed_by_signal": None,
              "thresholds": {"suspicious": 21, "malicious": 61},
              "verdict": None, "score": 0, "static_score": 0, "dynamic_score": 0,
              "dynamic_ran": False, "duration_seconds": 0, "behavior": None,
              "reasons": [], "findings": [], "timeline": [],
              "notes": [], "sandbox_log": "", "error": None}

    def finish(code):
        result["duration_seconds"] = round(time.time() - started, 1)
        if q:
            print(json.dumps(result))
        sys.exit(code)

    path = os.path.abspath(args.file)
    if not os.path.isfile(path):
        result["error"] = f"{path} is not a file"
        log("error: " + result["error"], q)
        finish(3)

    needs_root = not args.static_only
    if needs_root and os.geteuid() != 0:
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

    try:
        kind, interp = detect_type(path)
        result["sha256"] = sha256_of(path)
        result["file_type"] = kind + (f" ({interp})" if interp else "")
        result["size_bytes"] = os.path.getsize(path)
        log(f"[scan] file   : {path}", q)
        log(f"[scan] sha256 : {result['sha256']}", q)
        log(f"[scan] type   : {result['file_type']}", q)

        static_findings = static_scan(path)
        result["static_score"] = min(sum(f["points"] for f in static_findings), 100)
        result["findings"].extend(static_findings)

        fully_checked = False
        if args.static_only:
            result["notes"].append("Static checks only (--static-only). The file was not run.")
        elif kind in ("elf", "script"):
            ran, dscore, dfind, timeline, tail, behavior, exit_code, killed_by_signal = run_in_sandbox(
                path, kind, interp, args, q, result["notes"])
            result["dynamic_ran"] = ran
            result["dynamic_score"] = dscore
            result["findings"].extend(dfind)
            result["timeline"] = timeline
            result["sandbox_log"] = tail
            result["behavior"] = behavior
            if killed_by_signal:
                result["killed_by_signal"] = killed_by_signal
                result["exit_code"] = None
            else:
                result["exit_code"] = exit_code
                result["killed_by_signal"] = None
            fully_checked = ran
        elif kind == "source":
            result["notes"].append("This is source code, not a program, so it was not run. "
                                   "Compile it first (C++: g++ -static -O2 -o myprog file.cpp   "
                                   "C: gcc -static -O2 -o myprog file.c) and scan the compiled file.")
        else:
            what = "a Windows program" if kind == "pe" else "not a program or script"
            result["notes"].append(f"This file is {what}, so it was not run. Only static checks "
                                   f"were done.")

        for f in result["findings"]:
            if "category" not in f:
                f["category"] = _categorize(f)
        result["findings"].sort(key=lambda f: -f["points"])
        result["reasons"] = [
            {"category": f.get("category", "process"),
             "points": f.get("points", 0),
             "reason": f.get("reason", "")}
            for f in result["findings"]
        ]
        total = min(result["static_score"] + result["dynamic_score"], 100)
        result["score"] = total
        result["verdict"], code = verdict_for(total, fully_checked)
    except Exception as e:  # report the failure instead of a stack trace
        result["error"] = f"{type(e).__name__}: {e}"
        log("error: " + result["error"], q)
        finish(3)

    log("\n================ SENTRY VERDICT ================", q)
    log(f"  {result['verdict']}   (score {result['score']}/100: static "
        f"{result['static_score']} + behaviour {result['dynamic_score']})", q)
    for f in result["findings"]:
        pts = f"+{f['points']}" if f["points"] else "  "
        log(f"   {pts:>4}  [{f['source']}] {f['reason']}", q)
    if not result["findings"]:
        log("   nothing suspicious found", q)
    for n in result["notes"]:
        log(f"  note: {n}", q)
    if result["verdict"] == "NO ISSUES OBSERVED":
        log("\n  This means nothing bad was seen in a short run. It is not a guarantee.", q)
    log("================================================", q)
    finish(code)


if __name__ == "__main__":
    main()