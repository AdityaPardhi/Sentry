#!/usr/bin/env python3
"""
sentry — Main CLI entry point for SENTRY sandbox and behavior monitor.

Combines the C sandbox isolation (Phases 1-3) with Python monitoring (Phase 4):
  Usage:
    python3 cli/sentry.py run <command> [args...] [--profile strict|normal|development]
                                                   [--seccomp minimal|standard|permissive]
                                                   [--db sentry.db] [--interval 1.0]
    python3 cli/sentry.py monitor <pid> [--interval 1.0] [--duration 30] [--db sentry.db]
    python3 cli/sentry.py report [--db sentry.db] [--pid <pid>]
"""

import os
import re
import sys
import time
import json
import signal
import argparse
import subprocess
import threading
from typing import Optional, List

# Ensure parent directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.database import SentryDB
from monitor.process_monitor import ProcessMonitor, ProcessSample
from monitor.file_monitor import FileMonitor, FileEvent
from monitor.network_monitor import NetworkMonitor, NetworkSample
from monitor.risk_engine import RiskEngine, RiskAssessment
from monitor.response_engine import ResponseEngine, Incident


def find_sandbox_binary(name: str = "sentry_sandbox_v3") -> str:
    """Finds the sandbox binary in bin/ or relative directories."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base_dir, "bin", name),
        os.path.join(base_dir, "bin", "sentry_sandbox_v2"),
        os.path.join(base_dir, "bin", "sentry_sandbox"),
    ]
    for c in candidates:
        if os.path.exists(c) and os.access(c, os.X_OK):
            return c
    raise FileNotFoundError(f"Sandbox binary '{name}' not found. Run 'make' first.")


def cmd_report(args: argparse.Namespace) -> None:
    """Prints a formatted report of recorded samples from the SQLite DB."""
    db = SentryDB(args.db)
    samples = db.get_process_samples(pid=args.pid, limit=args.limit)
    file_samples = db.get_file_samples(pid=args.pid, limit=args.limit)
    file_events = db.get_file_events(limit=args.limit)
    net_samples = db.get_network_samples(pid=args.pid, limit=args.limit)
    risk_scores = db.get_risk_scores(pid=args.pid, limit=args.limit)

    if not samples and not file_samples and not net_samples and not risk_scores:
        print(f"[sentry report] No samples found in {args.db}.")
        return

    if samples:
        print("=" * 86)
        print(f" SENTRY Process Telemetry Report ({len(samples)} samples from {args.db})")
        print("=" * 86)
        print(f"{'ID':<6} {'PID':<8} {'Timestamp':<20} {'CPU %':<10} {'RSS (KB)':<12} {'Children':<10} {'Spawn Rate':<10}")
        print("─" * 86)

        max_cpu = 0.0
        max_rss = 0
        max_children = 0
        total_spawns = 0

        for s in samples:
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s["timestamp"]))
            print(f"{s['id']:<6} {s['pid']:<8} {t_str:<20} {s['cpu_percent']:<10.1f} {s['rss_kb']:<12} {s['child_count']:<10} {s['spawn_rate']:<10}")
            if s["cpu_percent"] > max_cpu:
                max_cpu = s["cpu_percent"]
            if s["rss_kb"] > max_rss:
                max_rss = s["rss_kb"]
            if s["child_count"] > max_children:
                max_children = s["child_count"]
            total_spawns += s["spawn_rate"]

        print("─" * 86)
        print(f" Summary: Peak CPU = {max_cpu:.1f}% | Peak RSS = {max_rss / 1024.0:.2f} MB | Max Active Children = {max_children} | Total Spawns = {total_spawns}")

    if file_samples or file_events:
        print("\n" + "=" * 86)
        print(f" SENTRY File Activity Report ({len(file_events)} events, {len(file_samples)} rate samples)")
        print("=" * 86)
        peak_rate = max((fs["file_write_rate"] for fs in file_samples), default=0.0)
        print(f" Peak File Write Rate: {peak_rate:.1f} files/min | Total File Events Logged: {len(file_events)}")
        if file_events:
            print(f"\n Latest File Events:")
            for fe in file_events[-5:]:
                t_str = time.strftime("%H:%M:%S", time.localtime(fe["timestamp"]))
                print(f"   [{t_str}] {fe['event_type']:<10} {fe['path']}")

    if net_samples:
        print("\n" + "=" * 86)
        print(f" SENTRY Network Activity Report ({len(net_samples)} rate samples)")
        print("=" * 86)
        peak_conn_rate = max((ns["connection_rate"] for ns in net_samples), default=0.0)
        peak_active = max((ns["active_connections"] for ns in net_samples), default=0)
        print(f" Peak Connection Rate: {peak_conn_rate:.1f} attempts/min | Peak Active Sockets: {peak_active}")

    if risk_scores:
        print("\n" + "=" * 86)
        print(f" SENTRY Risk Scoring Report ({len(risk_scores)} evaluations)")
        print("=" * 86)
        peak_score = max((rs["score"] for rs in risk_scores), default=0)
        max_band = max(risk_scores, key=lambda rs: rs["score"])["band"] if risk_scores else "NORMAL"
        print(f" Peak Risk Score: {peak_score}/100 | Peak Threat Band: {max_band}")
        latest = risk_scores[-1]
        try:
            rules = json.loads(latest.get("triggered_rules", "[]"))
            if rules:
                print(" Triggered Rules (latest evaluation):")
                for r in rules:
                    print(f"   • [{r.get('rule_name')}] +{r.get('points')} pts: {r.get('reason')}")
        except Exception:
            pass

    incidents = db.get_incidents(pid=args.pid, limit=args.limit)
    if incidents:
        print("\n" + "=" * 86)
        print(f" SENTRY Automatic Mitigation Incidents ({len(incidents)} actions taken)")
        print("=" * 86)
        for inc in incidents:
            ts = inc.get("timestamp")
            if isinstance(ts, (int, float)):
                t_str = time.strftime("%H:%M:%S", time.localtime(ts))
            else:
                dt = str(inc.get("detection_time") or inc.get("start_time") or "")
                t_str = dt.split()[-1] if " " in dt else (dt or time.strftime("%H:%M:%S"))
            res_str = inc.get("resolution", "PENDING")
            pre_val = inc.get("pre_metric", 0.0)
            post_val = inc.get("post_metric", 0.0)
            print(f"   [{t_str}] Band: {inc['band']:<8} | Status: {res_str:<10} | Action: {inc['action_taken']:<26} | Pre: {pre_val:.1f} -> Post: {post_val:.1f}")
            if inc.get("details"):
                print(f"            └─ {inc['details']}")

    print("=" * 86)


def render_ascii_bar(pct: float, width: int = 16) -> str:
    """Renders a visual progress bar e.g. [██████░░░░░░░░░░]."""
    clamped = max(0.0, min(100.0, pct))
    filled = int(round((clamped / 100.0) * width))
    bar = "█" * filled + "░" * (width - filled)
    return f"[{bar}]"


def print_status_snapshot(db: SentryDB) -> None:
    """Renders a rich single status dashboard view."""
    proc_samples = db.get_process_samples(limit=1)
    file_samples = db.get_file_samples(limit=1)
    net_samples = db.get_network_samples(limit=1)
    risk_scores = db.get_risk_scores(limit=1)
    incidents = db.get_incidents(limit=5)

    latest_proc = proc_samples[-1] if proc_samples else None
    latest_file = file_samples[-1] if file_samples else None
    latest_net = net_samples[-1] if net_samples else None
    latest_risk = risk_scores[-1] if risk_scores else None

    is_active = False
    pid_str = "None"
    cpu_val = 0.0
    rss_mb = 0.0
    children = 0
    f_rate = 0.0
    n_rate = 0.0
    n_active = 0
    score = 0
    band = "NORMAL"
    rules_text = "None (baseline clean)"

    if latest_proc:
        pid_str = str(latest_proc["pid"])
        is_active = os.path.exists(f"/proc/{latest_proc['pid']}")
        cpu_val = latest_proc["cpu_percent"]
        rss_mb = latest_proc["rss_kb"] / 1024.0
        children = latest_proc["child_count"]

    if latest_file:
        f_rate = latest_file["file_write_rate"]
    if latest_net:
        n_rate = latest_net["connection_rate"]
        n_active = latest_net["active_connections"]
    if latest_risk:
        score = latest_risk["score"]
        band = latest_risk["band"]
        try:
            r_list = json.loads(latest_risk.get("triggered_rules", "[]"))
            if r_list:
                rules_text = ", ".join(f"[{r.get('rule_name')}] +{r.get('points')}pts" for r in r_list)
        except Exception:
            pass

    status_tag = "ACTIVE [RUNNING]" if is_active else "IDLE / TERMINATED"
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "╔" + "═" * 78 + "╗")
    print("║" + "             SENTRY SANDBOX & BEHAVIOR MONITOR — STATUS DASHBOARD             ".center(78) + "║")
    print("╠" + "═" * 78 + "╣")
    print(f"║ System Time   : {now_str:<30} Sandbox State: {status_tag:<22} ║")
    print(f"║ Target Process: PID {pid_str:<26} Database     : {db.db_path:<22} ║")
    print("╟" + "─" * 78 + "╢")
    print("║ [RESOURCE TELEMETRY]                                                         ║")
    cpu_bar = render_ascii_bar(cpu_val)
    print(f"║   CPU Usage     : {cpu_bar} {cpu_val:5.1f}%                                          ║")
    rss_pct = min(100.0, (rss_mb / 1024.0) * 100.0)
    rss_bar = render_ascii_bar(rss_pct)
    print(f"║   Memory RSS    : {rss_bar} {rss_mb:6.1f} MB (Profile Cap: 1024 MB)                  ║")
    print(f"║   Child Procs   : {children:<3} active children (Cgroup Limit: 30 pids.max)            ║")
    print(f"║   File Activity : {f_rate:<6.1f} files/min                                              ║")
    print(f"║   Network Rate  : {n_rate:<6.1f} conn/min ({n_active} active sockets)                         ║")
    print("╟" + "─" * 78 + "╢")
    print("║ [THREAT ASSESSMENT & RISK SCORING]                                           ║")
    risk_bar = render_ascii_bar(score)
    print(f"║   Threat Band   : {band:<10} Score: {risk_bar} {score:>3}/100                 ║")
    print(f"║   Triggered     : {rules_text[:58]:<58} ║")
    print("╟" + "─" * 78 + "╢")
    print("║ [FORENSIC INCIDENT LOG (LATEST MITIGATIONS)]                                 ║")
    if incidents:
        for inc in incidents[:4]:
            ts = inc.get("timestamp")
            if isinstance(ts, (int, float)):
                t_s = time.strftime("%H:%M:%S", time.localtime(ts))
            else:
                dt = str(inc.get("detection_time") or inc.get("start_time") or "")
                t_s = dt.split()[-1] if " " in dt else (dt or time.strftime("%H:%M:%S"))
            res = inc.get("resolution", "ACTED")
            act = inc["action_taken"][:22]
            line_str = f"#{inc['id']} [{t_s}] {inc['band']:<8} {act:<22} {res}"
            print(f"║   {line_str:<74} ║")
    else:
        print("║   No security incidents recorded. System nominal.                            ║")
    print("╟" + "─" * 78 + "╢")
    print("║ [PROCESS HIERARCHY TREE]                                                     ║")
    if latest_proc and latest_proc['pid']:
        r_pid = latest_proc['pid']
        print(f"║   └── [PID {r_pid}] sandboxed_process (root)                                    ║")
        if children > 0:
            for c_i in range(min(children, 5)):
                prefix = "└──" if (c_i == min(children, 5) - 1 and children <= 5) else "├──"
                print(f"║       {prefix} [PID {r_pid + 1 + c_i}] child_worker_{c_i+1}                                  ║")
            if children > 5:
                print(f"║       └── ... ({children - 5} additional child processes)                       ║")
    else:
        print("║   No active process hierarchy available.                                     ║")
    print("╚" + "═" * 78 + "╝")


def cmd_status(args: argparse.Namespace) -> None:
    """Live status view of SENTRY sandbox telemetry and incident log."""
    db = SentryDB(args.db)
    if args.once:
        print_status_snapshot(db)
        return

    print(f"[sentry] Entering live status monitor loop (interval: {args.interval}s, press Ctrl+C to exit)...")
    try:
        while True:
            if sys.stdout.isatty():
                sys.stdout.write("\033[H\033[J")
            print_status_snapshot(db)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[sentry] Exiting status view.")


def cmd_monitor(args: argparse.Namespace) -> None:
    """Attaches monitor to an existing PID."""
    if not os.path.exists(f"/proc/{args.pid}"):
        print(f"Error: Process PID {args.pid} does not exist.", file=sys.stderr)
        sys.exit(1)

    db = SentryDB(args.db)
    monitor = ProcessMonitor(pid=args.pid, db=db)
    print(f"[sentry] Monitoring PID {args.pid} -> logging to {args.db}")
    monitor.monitor_loop(interval=args.interval, duration=args.duration)


def cmd_run(args: argparse.Namespace, remaining_cmd: List[str]) -> None:
    """Launches command in the sandbox while concurrently monitoring it."""
    if not remaining_cmd:
        print("Error: No command specified to run.", file=sys.stderr)
        sys.exit(1)

    sandbox_bin = find_sandbox_binary()
    db = SentryDB(args.db)
    sandbox_root = os.environ.get("SENTRY_ROOT", "/opt/sentry/sandbox-root")

    # Build sandbox invocation: sudo ./bin/sentry_sandbox_v3 run <cmd...> --profile <p> --seccomp <s>
    cmd_line = [sandbox_bin, "run"] + remaining_cmd
    if args.profile:
        cmd_line.extend(["--profile", args.profile])
    if args.seccomp:
        cmd_line.extend(["--seccomp", args.seccomp])

    # SENTRY sandbox requires root (namespaces + cgroups)
    if os.geteuid() != 0:
        cmd_line = ["sudo"] + cmd_line

    print(f"[sentry] Starting sandbox command: {' '.join(cmd_line)}")
    print(f"[sentry] Telemetry will be logged to SQLite DB: {args.db}")

    # Pre-initialize file monitor on sandbox root before launch
    file_mon: Optional[FileMonitor] = None
    try:
        file_mon = FileMonitor(root_dir=sandbox_root, db=db)
    except Exception as e:
        file_mon = None

    # Part 1.5 — Set up a pipe for the trusted control channel.
    # The C sandbox binary writes "PID:<child_pid>\n" to the write end
    # before calling execve.  We read from the read end.
    ctrl_rd, ctrl_wr = os.pipe()

    # Launch process — pass the write end of the pipe as --control-fd
    cmd_line_ctrl = cmd_line + ["--control-fd", str(ctrl_wr)]
    proc = subprocess.Popen(
        cmd_line_ctrl,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        bufsize=1,
        pass_fds=(ctrl_wr,),
        start_new_session=True,
    )
    # Parent closes its copy of the write end — child has the only reference
    os.close(ctrl_wr)

    child_pid: Optional[int] = None
    monitor_thread: Optional[threading.Thread] = None
    stop_event = threading.Event()
    net_mon: Optional[NetworkMonitor] = None
    risk_engine: Optional[RiskEngine] = None
    response_engine: Optional[ResponseEngine] = None

    def monitor_worker(pid: int, pm: ProcessMonitor, t0: float):
        nonlocal net_mon, risk_engine, response_engine
        while not stop_event.is_set():
            stop_event.wait(args.interval)
            if stop_event.is_set():
                break

            p_sample = pm.sample()
            f_rate = 0.0
            if file_mon:
                f_rate, _ = file_mon.sample()
            n_sample = net_mon.sample()

            assessment = risk_engine.evaluate(
                proc_sample=p_sample,
                file_rate=f_rate,
                conn_rate=n_sample.connection_rate,
                active_conns=n_sample.active_connections,
                seccomp_killed=False
            )

            # Automated mitigation action (simplified — no escalation loop)
            pre_metric = max(p_sample.cpu_percent, f_rate, n_sample.connection_rate)
            incident = response_engine.act(
                assessment,
                target_pid=pid,
                pre_metric=pre_metric,
                executable=remaining_cmd[0] if remaining_cmd else "unknown",
                cpu_percent=p_sample.cpu_percent,
                rss_kb=p_sample.rss_kb,
                child_count=p_sample.child_count,
                file_write_rate=f_rate,
                connection_attempts=n_sample.active_connections
            )
            if incident:
                print(f"\n  [sentry ALERT] Threat Band {incident.band} -> Mitigation: {incident.action_taken} ({incident.details})")
                sys.stdout.flush()

            elapsed = p_sample.timestamp - t0
            rss_mb = p_sample.rss_kb / 1024.0
            print(
                f"{elapsed:5.1f}s  "
                f"{p_sample.pid:<6} "
                f"{p_sample.cpu_percent:6.1f}%  "
                f"{rss_mb:7.2f}  "
                f"{p_sample.child_count:<6} "
                f"{f_rate:8.1f}  "
                f"{n_sample.connection_rate:7.1f}  "
                f"{assessment.score:<6} "
                f"{assessment.band}"
            )
            sys.stdout.flush()

            if not p_sample.is_alive:
                break

    # Part 1.5 — seccomp kill now detected only from exit status (SIGSYS == signal 31),
    # NOT from stdout parsing, to avoid trusting sandboxed program output for security.
    seccomp_killed = False
    lifecycle_lines = []
    cmd_output_lines = []

    # Part 1.5 — Read child PID from the trusted control channel (non-blocking with timeout)
    def read_control_pid(fd: int, timeout: float = 5.0) -> Optional[int]:
        """Reads 'PID:<n>\n' from the control fd with a timeout."""
        import select
        buf = b""
        deadline = time.time() + timeout
        try:
            while time.time() < deadline:
                remaining = deadline - time.time()
                r, _, _ = select.select([fd], [], [], max(0.0, remaining))
                if not r:
                    break
                chunk = os.read(fd, 64)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in buf:
                    break
        except OSError:
            pass
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
        line = buf.decode(errors="replace").strip()
        if line.startswith("PID:"):
            try:
                return int(line[4:])
            except ValueError:
                pass
        return None

    def is_lifecycle_line(l_str: str) -> bool:
        s = l_str.strip()
        return (
            s.startswith("[sentry] ───") or
            s.startswith("[sentry] Sandbox exited") or
            s.startswith("[sentry] Sandbox session ended") or
            s.startswith("[sentry] *** SIG") or
            s.startswith("[sentry] Sandbox killed") or
            s.startswith("[sentry] Sandbox stopped") or
            s.startswith("[cgroup] Cgroup removed")
        )

    # Part 4 — Wall-clock timeout watcher (default 30 s)
    timeout_fired = False
    def timeout_watcher():
        nonlocal timeout_fired
        t_limit = getattr(args, "timeout", 30.0)
        if t_limit and t_limit > 0:
            if stop_event.wait(t_limit):
                return
            timeout_fired = True
            if child_pid:
                try:
                    os.kill(child_pid, getattr(signal, "SIGKILL", 9))
                except Exception:
                    pass
            try:
                proc.terminate()
            except Exception:
                pass

    timeout_thread = None
    if getattr(args, "timeout", 30.0):
        timeout_thread = threading.Thread(target=timeout_watcher, daemon=True)
        timeout_thread.start()

    try:
        assert proc.stdout is not None

        # Part 1.5 — Read the trusted PID from the control channel FIRST
        child_pid = read_control_pid(ctrl_rd)
        if child_pid is not None:
            # Initialize monitors
            proc_mon = ProcessMonitor(pid=child_pid, db=db)
            net_mon = NetworkMonitor(pid=child_pid, db=db)
            risk_engine = RiskEngine(pid=child_pid, db=db)
            response_engine = ResponseEngine(db=db, cgroup_path=f"/sys/fs/cgroup/sentry_{child_pid}")
            if file_mon:
                file_mon.monitored_pid = child_pid

            # Print telemetry table header
            print(f"\n[sentry monitor] Attached to PID {child_pid} + watching '{sandbox_root}' (interval: {args.interval}s)")
            print(f"{'Time':<7} {'PID':<6} {'CPU %':<8} {'RSS(MB)':<9} {'Procs':<6} {'Files/min':<10} {'Conn/min':<9} {'Risk':<6} {'Band'}")
            print("─" * 80)
            sys.stdout.flush()

            # Take first sample immediately at t=0.0s
            start_time = time.time()
            p_sample = proc_mon.sample()
            f_rate = 0.0
            if file_mon:
                f_rate, _ = file_mon.sample()
            n_sample = net_mon.sample()

            assessment = risk_engine.evaluate(
                proc_sample=p_sample,
                file_rate=f_rate,
                conn_rate=n_sample.connection_rate,
                active_conns=n_sample.active_connections,
                seccomp_killed=False
            )

            pre_metric = max(p_sample.cpu_percent, f_rate, n_sample.connection_rate)
            incident = response_engine.act(
                assessment,
                target_pid=child_pid,
                pre_metric=pre_metric,
                executable=remaining_cmd[0] if remaining_cmd else "unknown",
                cpu_percent=p_sample.cpu_percent,
                rss_kb=p_sample.rss_kb,
                child_count=p_sample.child_count,
                file_write_rate=f_rate,
                connection_attempts=n_sample.active_connections
            )
            if incident:
                print(f"\n  [sentry ALERT] Threat Band {incident.band} -> Mitigation: {incident.action_taken} ({incident.details})")
                sys.stdout.flush()

            rss_mb = p_sample.rss_kb / 1024.0
            print(
                f"{0.0:5.1f}s  "
                f"{p_sample.pid:<6} "
                f"{p_sample.cpu_percent:6.1f}%  "
                f"{rss_mb:7.2f}  "
                f"{p_sample.child_count:<6} "
                f"{f_rate:8.1f}  "
                f"{n_sample.connection_rate:7.1f}  "
                f"{assessment.score:<6} "
                f"{assessment.band}"
            )
            sys.stdout.flush()

            # If still alive, start background worker for subsequent samples
            if p_sample.is_alive:
                monitor_thread = threading.Thread(
                    target=monitor_worker,
                    args=(child_pid, proc_mon, start_time),
                    daemon=True
                )
                monitor_thread.start()

        # Stream sandbox stdout to console
        for line in proc.stdout:
            if is_lifecycle_line(line):
                lifecycle_lines.append(line)
            elif line.strip():
                cmd_output_lines.append(line)

        # Detect seccomp kill from process exit signal (trustworthy — from kernel)
        proc.wait()
        if proc.returncode is not None and proc.returncode == -(signal.SIGSYS):
            seccomp_killed = True
    except KeyboardInterrupt:
        print("\n[sentry] Interrupted by user. Terminating sandbox...")
        stop_event.set()
        if monitor_thread and monitor_thread.is_alive():
            monitor_thread.join(timeout=2.0)
        try:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1.0)
        except Exception:
            pass
    finally:
        stop_event.set()
        if monitor_thread and monitor_thread.is_alive():
            monitor_thread.join(timeout=2.0)
        if file_mon:
            file_mon.stop()
        if net_mon:
            net_mon.stop()
        if risk_engine and child_pid and seccomp_killed:
            try:
                final_assessment = risk_engine.evaluate(
                    proc_sample=None,
                    file_rate=0.0,
                    conn_rate=0.0,
                    active_conns=0,
                    seccomp_killed=True
                )
                if response_engine:
                    response_engine.act(
                        final_assessment,
                        target_pid=child_pid,
                        executable=remaining_cmd[0] if remaining_cmd else "unknown",
                        file_write_rate=0.0,
                        connection_attempts=0
                    )
            except Exception:
                pass

        # Cgroup cleanup after sandbox process ends by ANY path
        if child_pid:
            cgroup_path = f"/sys/fs/cgroup/sentry_{child_pid}"
            kill_file = os.path.join(cgroup_path, "cgroup.kill")
            if os.path.exists(kill_file):
                try:
                    with open(kill_file, "w") as f:
                        f.write("1")
                except OSError:
                    pass

            procs_file = os.path.join(cgroup_path, "cgroup.procs")
            deadline = time.time() + 2.0
            while time.time() < deadline:
                if not os.path.exists(procs_file):
                    break
                try:
                    with open(procs_file, "r") as f:
                        content = f.read().strip()
                    if not content:
                        break
                except (FileNotFoundError, ProcessLookupError):
                    break
                except OSError:
                    pass
                time.sleep(0.1)

            try:
                os.rmdir(cgroup_path)
            except FileNotFoundError:
                pass
            except OSError as e:
                print(f"[sentry] Warning: failed to remove cgroup {cgroup_path}: {e}", file=sys.stderr)

    # Print any command output
    if cmd_output_lines:
        for coline in cmd_output_lines:
            sys.stdout.write(coline)
        sys.stdout.flush()

    # Print lifecycle messages (exit status + cgroup cleanup)
    if lifecycle_lines:
        print()
        for lline in lifecycle_lines:
            sys.stdout.write(lline)
        sys.stdout.flush()

    if timeout_fired:
        print(f"[sentry] Execution timed out after {args.timeout} seconds.")

    print(f"\n[sentry] Process exited with status {proc.returncode}")

    # If the sandbox binary never emitted a child PID the cgroup/namespace
    # setup failed.  Exit non-zero so callers (evaluate_comparison.py) can
    # detect the failure reliably — regardless of what the sandbox binary
    # itself reported as its own exit code.
    if child_pid is None:
        print(
            "[sentry] ERROR: Sandbox never reported a child PID. "
            "The sandbox likely failed to initialise (cgroup v2, binary path, "
            "or permissions issue). No telemetry was collected.",
            file=sys.stderr,
        )
        sys.exit(1)

    if child_pid:
        # Show brief summary from DB
        samples = db.get_process_samples(pid=child_pid)
        file_samples = db.get_file_samples(pid=child_pid)
        net_samples = db.get_network_samples(pid=child_pid)
        risk_scores = db.get_risk_scores(pid=child_pid)
        incidents = db.get_incidents(pid=child_pid)
        if samples:
            peak_cpu = max(s["cpu_percent"] for s in samples)
            peak_rss = max(s["rss_kb"] for s in samples) / 1024.0
            peak_f_rate = max((fs["file_write_rate"] for fs in file_samples), default=0.0)
            peak_n_rate = max((ns["connection_rate"] for ns in net_samples[1:]), default=0.0) if len(net_samples) > 1 else 0.0
            peak_risk = max((rs["score"] for rs in risk_scores), default=0)
            max_band = max(risk_scores, key=lambda rs: rs["score"])["band"] if risk_scores else "NORMAL"
            print(f"[sentry telemetry] Recorded {len(samples)} samples for PID {child_pid}:")
            print(f"                   Peak CPU: {peak_cpu:.1f}% | Peak RSS: {peak_rss:.2f} MB")
            print(f"                   Peak File Rate: {peak_f_rate:.1f} files/min | Peak Conn Rate: {peak_n_rate:.1f} conn/min")
            print(f"                   Peak Risk Score: {peak_risk}/100 ({max_band})")
            if incidents:
                print(f"                   Mitigation Actions: {len(incidents)} automated responses executed")


def main():
    parser = argparse.ArgumentParser(
        description="SENTRY — Secure Linux Sandbox & Malware Behavior Monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Command: run
    p_run = subparsers.add_parser("run", help="Launch a program in the SENTRY sandbox with live monitoring")
    p_run.add_argument("--profile", choices=["strict", "normal", "development"], default="normal",
                       help="Resource profile (default: normal)")
    p_run.add_argument("--seccomp", choices=["minimal", "standard", "permissive"], default="standard",
                       help="Seccomp policy mode (default: standard)")
    p_run.add_argument("--db", default="sentry.db", help="SQLite database path (default: sentry.db)")
    p_run.add_argument("--interval", type=float, default=1.0, help="Monitoring sample interval in seconds (default: 1.0)")
    p_run.add_argument("--timeout", type=float, default=30.0,
                       help="Maximum execution duration in seconds before terminating sandbox (default: 30.0s)")

    # Command: monitor
    p_mon = subparsers.add_parser("monitor", help="Monitor an existing process PID")
    p_mon.add_argument("pid", type=int, help="Target process PID")
    p_mon.add_argument("--interval", type=float, default=1.0, help="Sample interval (default: 1.0s)")
    p_mon.add_argument("--duration", type=float, default=None, help="Monitoring duration in seconds")
    p_mon.add_argument("--db", default="sentry.db", help="SQLite database path (default: sentry.db)")

    # Command: report
    p_rep = subparsers.add_parser("report", help="View recorded telemetry samples")
    p_rep.add_argument("--db", default="sentry.db", help="SQLite database path (default: sentry.db)")
    p_rep.add_argument("--pid", type=int, default=None, help="Filter by PID")
    p_rep.add_argument("--limit", type=int, default=200, help="Maximum number of samples to show (default: 200)")
    # Command: status (Phase 13: Live status dashboard)
    p_stat = subparsers.add_parser("status", help="Live status dashboard of sandbox telemetry and security incidents")
    p_stat.add_argument("--db", default="sentry.db", help="SQLite database path (default: sentry.db)")
    p_stat.add_argument("--interval", type=float, default=1.0, help="Refresh interval in seconds (default: 1.0)")
    p_stat.add_argument("--once", action="store_true", help="Print single snapshot and exit")

    args, remaining = parser.parse_known_args()

    if args.command == "run":
        cmd_run(args, remaining)
    elif args.command == "monitor":
        cmd_monitor(args)
    elif args.command == "report":
        cmd_report(args)
    elif args.command == "status":
        cmd_status(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
