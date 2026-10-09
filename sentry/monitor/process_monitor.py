"""
process_monitor.py — Phase 4: Process Behavior Monitor

Monitors a sandboxed process and its child tree at the OS level:
  - Step 4.1: Reads /proc/<pid>/stat for CPU %
  - Step 4.2: Reads /proc/<pid>/status for VmRSS (Resident Set Size in KB)
  - Step 4.3: Tracks child process creation (process tree and spawn rate)
  - Step 4.4: Logs time-series data at intervals to SQLite (process_samples table)

No scoring or decision logic yet — just clean data collection.
"""

import os
import sys
import time
import argparse
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass

# Allow importing SentryDB whether invoked directly or as a package
try:
    from db.database import SentryDB
except ImportError:
    try:
        from sentry.db.database import SentryDB
    except ImportError:
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from db.database import SentryDB


@dataclass
class ProcessSample:
    """Represents a single metric sample for a process tree."""
    pid: int
    timestamp: float
    cpu_percent: float
    rss_kb: int
    child_count: int
    spawn_rate: int
    tree: Dict[int, List[int]]
    is_alive: bool


class ProcessMonitor:
    """
    Continuously monitors a target PID and its child process tree via /proc.
    """

    def __init__(self, pid: int, db: Optional[SentryDB] = None, clk_tck: Optional[int] = None):
        self.root_pid = pid
        self.db = db

        # Clock ticks per second (usually 100 on Linux x86_64)
        if clk_tck is not None:
            self.clk_tck = clk_tck
        else:
            try:
                self.clk_tck = os.sysconf(os.sysconf_names.get('SC_CLK_TCK', 'SC_CLK_TCK'))
            except (AttributeError, ValueError):
                self.clk_tck = 100

        # State tracking for CPU calculations: pid -> (utime + stime)
        self.prev_ticks: Dict[int, int] = {}
        self.prev_sample_time: Optional[float] = None

        # State tracking for child spawn rate
        # All PIDs ever observed in the monitored process tree
        self.seen_pids: Set[int] = {self.root_pid}

    def is_process_alive(self, pid: Optional[int] = None) -> bool:
        """Checks if a process exists in /proc."""
        target = pid if pid is not None else self.root_pid
        return os.path.exists(f"/proc/{target}")

    def _read_proc_stat(self, pid: int) -> Optional[Tuple[int, int, int]]:
        """
        Reads /proc/<pid>/stat.
        Returns (ppid, utime, stime) in clock ticks, or None if process exited.
        Safely parses past the comm field which may contain spaces and parentheses.
        """
        stat_path = f"/proc/{pid}/stat"
        try:
            with open(stat_path, "r") as f:
                content = f.read().strip()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            return None

        # Find the last closing parenthesis to skip the comm field (e.g. '(bash)')
        rparen_idx = content.rfind(")")
        if rparen_idx == -1:
            return None

        remaining = content[rparen_idx + 2:].split()
        if len(remaining) < 14:
            return None

        try:
            ppid = int(remaining[1])    # field 4 of /proc/<pid>/stat
            utime = int(remaining[11])  # field 14: user ticks
            stime = int(remaining[12])  # field 15: kernel ticks
            return ppid, utime, stime
        except (ValueError, IndexError):
            return None

    def _read_proc_rss(self, pid: int) -> int:
        """
        Reads /proc/<pid>/status and extracts VmRSS in KB.
        Returns 0 if not present or process exited.
        """
        status_path = f"/proc/{pid}/status"
        try:
            with open(status_path, "r") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return int(parts[1])
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
            return 0
        return 0

    def _get_direct_children(self, pid: int) -> List[int]:
        """
        Finds direct child PIDs of `pid`.
        First tries /proc/<pid>/task/<pid>/children.
        If unavailable, falls back to scanning /proc for processes with matching PPID.
        """
        children_path = f"/proc/{pid}/task/{pid}/children"
        if os.path.exists(children_path):
            try:
                with open(children_path, "r") as f:
                    line = f.read().strip()
                    if line:
                        return [int(p) for p in line.split() if p.isdigit()]
                    return []
            except (FileNotFoundError, PermissionError):
                pass

        # Fallback: scan all /proc/[0-9]*/stat
        children = []
        try:
            for entry in os.listdir("/proc"):
                if entry.isdigit():
                    c_pid = int(entry)
                    stat_info = self._read_proc_stat(c_pid)
                    if stat_info and stat_info[0] == pid:
                        children.append(c_pid)
        except (FileNotFoundError, PermissionError):
            pass
        return children

    def build_process_tree(self) -> Tuple[Dict[int, List[int]], List[int]]:
        """
        Builds the process tree rooted at self.root_pid.
        Returns:
          tree: dict of parent_pid -> list of child_pids
          all_descendants: list of all descendant child PIDs
        """
        tree: Dict[int, List[int]] = {}
        all_descendants: List[int] = []

        if not self.is_process_alive(self.root_pid):
            return tree, all_descendants

        queue = [self.root_pid]
        while queue:
            curr = queue.pop(0)
            children = self._get_direct_children(curr)
            tree[curr] = children
            for child in children:
                if child not in all_descendants and child != self.root_pid:
                    all_descendants.append(child)
                    queue.append(child)

        return tree, all_descendants

    def sample(self) -> ProcessSample:
        """
        Takes one monitoring sample across the target process and its child tree:
          - Step 4.1: CPU % = (delta_ticks / clk_tck) / elapsed_seconds * 100
          - Step 4.2: RSS = sum of VmRSS across process tree
          - Step 4.3: Process tree, child count, and spawn rate
          - Step 4.4: Log to SQLite DB if configured
        """
        now = time.time()
        root_alive = self.is_process_alive(self.root_pid)

        # Step 4.3: Build process tree
        tree, descendants = self.build_process_tree()
        all_pids = [self.root_pid] + descendants if root_alive else descendants
        child_count = len(descendants)

        # Calculate spawn rate: new PIDs appearing since last sample
        current_pids_set = set(all_pids)
        new_pids = current_pids_set - self.seen_pids
        spawn_rate = len(new_pids)
        self.seen_pids.update(current_pids_set)

        # Step 4.1: Compute CPU ticks
        current_ticks: Dict[int, int] = {}
        total_ticks = 0

        for p in all_pids:
            stat_info = self._read_proc_stat(p)
            if stat_info:
                _, utime, stime = stat_info
                ticks = utime + stime
                current_ticks[p] = ticks
                total_ticks += ticks

        # Compute CPU%
        cpu_percent = 0.0
        if self.prev_sample_time is not None:
            elapsed = now - self.prev_sample_time
            if elapsed > 0:
                # Delta ticks across all tracked processes
                delta_ticks = 0
                for p, ticks in current_ticks.items():
                    prev = self.prev_ticks.get(p, 0)
                    if ticks >= prev:
                        delta_ticks += (ticks - prev)
                    else:
                        delta_ticks += ticks

                cpu_percent = (delta_ticks / self.clk_tck) / elapsed * 100.0
                if cpu_percent < 0.0:
                    cpu_percent = 0.0

        self.prev_ticks = current_ticks
        self.prev_sample_time = now

        # Step 4.2: Compute RSS memory
        total_rss_kb = 0
        for p in all_pids:
            total_rss_kb += self._read_proc_rss(p)

        # Step 4.4: Log to SQLite DB
        if self.db is not None:
            self.db.insert_process_sample(
                pid=self.root_pid,
                timestamp=now,
                cpu_percent=cpu_percent,
                rss_kb=total_rss_kb,
                child_count=child_count,
                spawn_rate=spawn_rate
            )

        return ProcessSample(
            pid=self.root_pid,
            timestamp=now,
            cpu_percent=cpu_percent,
            rss_kb=total_rss_kb,
            child_count=child_count,
            spawn_rate=spawn_rate,
            tree=tree,
            is_alive=root_alive or len(descendants) > 0
        )

    def monitor_loop(
        self,
        interval: float = 1.0,
        duration: Optional[float] = None,
        callback=None
    ) -> List[ProcessSample]:
        """
        Runs the monitoring loop at `interval` seconds until `duration` expires
        or the target process and all children exit.
        """
        samples: List[ProcessSample] = []
        start_time = time.time()

        print(f"[ProcessMonitor] Attached to PID {self.root_pid} (interval: {interval}s)")
        print(f"{'Time':<10} {'PID':<8} {'CPU %':<10} {'RSS (MB)':<12} {'Children':<10} {'Spawn Rate':<12} {'Status':<10}")
        print("─" * 76)

        try:
            while True:
                sample = self.sample()
                samples.append(sample)

                elapsed = sample.timestamp - start_time
                status = "ACTIVE" if sample.is_alive else "EXITED"
                rss_mb = sample.rss_kb / 1024.0

                print(
                    f"{elapsed:8.1f}s  "
                    f"{sample.pid:<8} "
                    f"{sample.cpu_percent:8.1f}%  "
                    f"{rss_mb:10.2f}  "
                    f"{sample.child_count:<10} "
                    f"{sample.spawn_rate:<12} "
                    f"{status:<10}"
                )
                sys.stdout.flush()

                if callback:
                    callback(sample)

                if not sample.is_alive:
                    print(f"[ProcessMonitor] Monitored process PID {self.root_pid} exited.")
                    break

                if duration is not None and (time.time() - start_time) >= duration:
                    print(f"[ProcessMonitor] Duration {duration}s reached.")
                    break

                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n[ProcessMonitor] Monitoring stopped by user (SIGINT).")

        return samples


def main():
    parser = argparse.ArgumentParser(description="SENTRY Process Behavior Monitor (Phase 4)")
    parser.add_argument("pid", type=int, help="Target process PID to monitor")
    parser.add_argument("--interval", type=float, default=1.0, help="Sampling interval in seconds (default: 1.0)")
    parser.add_argument("--duration", type=float, default=None, help="Total duration to monitor in seconds")
    parser.add_argument("--db", type=str, default="sentry.db", help="Path to SQLite database (default: sentry.db)")
    args = parser.parse_args()

    if not os.path.exists(f"/proc/{args.pid}"):
        print(f"Error: Process with PID {args.pid} does not exist in /proc.", file=sys.stderr)
        sys.exit(1)

    db = SentryDB(args.db)
    monitor = ProcessMonitor(pid=args.pid, db=db)
    monitor.monitor_loop(interval=args.interval, duration=args.duration)


if __name__ == "__main__":
    main()
