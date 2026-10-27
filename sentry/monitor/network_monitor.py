"""
network_monitor.py — Phase 6: Network Behavior Monitor

Change (changes.md Part 4):
  The sandbox has no real network interface (it runs in an isolated network
  namespace with loopback only).  TCP/UDP polling via /proc/net/tcp[6] always
  reflected host traffic, not sandbox traffic.

  Updated to watch AF_UNIX socket activity inside the sandbox's network
  namespace via /proc/<pid>/net/unix:
    - Counts active Unix-domain sockets.
    - Tracks new socket paths (inode signatures) as "connection attempts".
    - Computes attempts-per-minute over a 60-second rolling window.
    - Logs samples to the network_samples table in SQLite.

Zero external dependencies — pure Python standard library.
"""

import os
import sys
import time
import json
import threading
from collections import deque
from typing import List, Optional, Set, Deque
from dataclasses import dataclass

# Allow importing SentryDB
try:
    from db.database import SentryDB
except ImportError:
    try:
        from sentry.db.database import SentryDB
    except ImportError:
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from db.database import SentryDB


# AF_UNIX socket state codes from /proc/<pid>/net/unix
# Field 5 (0-indexed) is the socket state:
UNIX_STATES = {
    "0": "FREE",
    "1": "UNCONNECTED",
    "2": "CONNECTING",
    "3": "CONNECTED",
    "4": "DISCONNECTING",
}

# States considered "active" (has a peer or is in transition)
UNIX_ACTIVE_STATES = {"2", "3", "4"}


@dataclass
class SocketInfo:
    """Represents one AF_UNIX socket entry from /proc/<pid>/net/unix."""
    inode: str
    path: str        # Socket filesystem path (may be empty for anonymous sockets)
    state_code: str
    state_name: str
    flags: str       # Raw flags field
    socket_type: str # SOCK_STREAM / SOCK_DGRAM etc.



@dataclass
class NetworkSample:
    pid: Optional[int]
    timestamp: float
    active_connections: int      # Active AF_UNIX sockets
    connection_rate: float       # New AF_UNIX sockets per minute
    syn_sent_count: int          # Kept for API compatibility (always 0 for unix)
    destinations: List[str]      # Socket paths observed


class NetworkMonitor:
    """
    Monitors AF_UNIX sockets of a sandboxed process via /proc/<pid>/net/unix.

    The sandbox runs in an isolated network namespace (loopback only), so
    TCP/UDP polling of /proc/net/tcp[6] would reflect host traffic rather
    than sandbox traffic.  AF_UNIX socket monitoring correctly captures
    IPC activity inside the sandbox's own namespace.
    """

    def __init__(self, pid: Optional[int] = None, db: Optional[SentryDB] = None):
        self.pid = pid
        self.db = db

        # Track previously observed socket inodes to detect newly opened sockets
        self.seen_sockets: Set[str] = set()
        self.prev_sockets: Optional[Set[str]] = None
        self.prev_sample_time: Optional[float] = None
        self.is_first_sample: bool = True
        self.current_rate: float = 0.0

        self.start_time = time.time()
        self.total_attempts = 0

        # Concurrency & background thread control
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def _get_unix_proc_path(self) -> Optional[str]:
        """Returns the /proc path for AF_UNIX sockets in the sandbox's namespace, or None."""
        if self.pid and os.path.exists(f"/proc/{self.pid}"):
            proc_path = f"/proc/{self.pid}/net/unix"
            if os.path.exists(proc_path):
                return proc_path
        return None

    def parse_unix_sockets(self) -> List[SocketInfo]:
        """
        Parses /proc/<pid>/net/unix for AF_UNIX socket entries.

        Format (from kernel docs):
          Num RefCount Protocol Flags Type St Inode Path
          0: 00000002 00000000 00010000 0001 01 12345 /run/dbus/system_bus_socket

        Returns a list of SocketInfo objects.
        """
        path = self._get_unix_proc_path()
        sockets: List[SocketInfo] = []

        if not path or not os.path.exists(path):
            return sockets

        try:
            with open(path, "r") as f:
                lines = f.readlines()
        except (FileNotFoundError, ProcessLookupError, PermissionError, OSError):
            return sockets

        if len(lines) <= 1:
            return sockets

        # Skip header line
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 7:
                continue
            try:
                # Fields: Num RefCount Protocol Flags Type St Inode [Path]
                flags     = parts[3]
                sock_type = parts[4]  # 0001=STREAM, 0002=DGRAM, 0005=SEQPACKET
                st_code   = parts[5]
                inode     = parts[6]
                sock_path = parts[7] if len(parts) > 7 else "(anonymous)"
                st_name   = UNIX_STATES.get(st_code, "UNKNOWN")

                type_names = {"0001": "STREAM", "0002": "DGRAM",
                              "0005": "SEQPACKET", "0003": "RAW"}
                type_str   = type_names.get(sock_type, sock_type)

                sockets.append(SocketInfo(
                    inode=inode,
                    path=sock_path,
                    state_code=st_code,
                    state_name=st_name,
                    flags=flags,
                    socket_type=type_str,
                ))
            except (ValueError, IndexError):
                continue

        return sockets

    def get_all_sockets(self) -> List[SocketInfo]:
        """Returns AF_UNIX sockets from the sandbox's network namespace."""
        return self.parse_unix_sockets()

    def get_rate(self) -> float:
        """Returns the current connection rate."""
        return self.current_rate

    def sample(self) -> NetworkSample:
        """
        Takes one AF_UNIX network monitoring sample:
          - Reads /proc/<pid>/net/unix only while /proc/<pid> exists; returns 0 otherwise.
          - Rate = NEW sockets since previous sample / real elapsed seconds (min 1.0s).
          - Skips the first sample (rate = 0.0).
          - Logs sample to SQLite only while process exists.
        """
        now = time.time()

        # Read /proc/<pid>/net/unix only while /proc/<pid> exists; return 0 otherwise and never fall back
        if not self.pid or not os.path.exists(f"/proc/{self.pid}"):
            return NetworkSample(
                pid=self.pid,
                timestamp=now,
                active_connections=0,
                connection_rate=0.0,
                syn_sent_count=0,
                destinations=[],
            )

        sockets = self.get_all_sockets()

        active_count = 0
        current_paths: Set[str] = set()
        current_inodes: Set[str] = set()

        for s in sockets:
            if s.state_code in UNIX_ACTIVE_STATES:
                active_count += 1
            current_inodes.add(s.inode)
            if s.path and s.path != "(anonymous)":
                current_paths.add(s.path)

        path_list = sorted(list(current_paths))

        with self._lock:
            if self.is_first_sample:
                self.is_first_sample = False
                self.prev_sockets = set(current_inodes)
                self.prev_sample_time = now
                rate = 0.0
            else:
                new_sockets = len(current_inodes - (self.prev_sockets or set()))
                elapsed = now - (self.prev_sample_time or now)
                elapsed_sec = max(elapsed, 1.0)
                rate = new_sockets / elapsed_sec
                self.prev_sockets = set(current_inodes)
                self.prev_sample_time = now
            self.current_rate = rate

        # Log sample to SQLite
        if self.db is not None:
            try:
                self.db.insert_network_sample(
                    timestamp=now,
                    active_connections=active_count,
                    connection_rate=rate,
                    syn_sent_count=0,
                    destinations=json.dumps(path_list),
                    pid=self.pid
                )
            except Exception as e:
                print(f"[NetworkMonitor ERROR] insert_network_sample failed: {e}", file=sys.stderr)

        return NetworkSample(
            pid=self.pid,
            timestamp=now,
            active_connections=active_count,
            connection_rate=rate,
            syn_sent_count=0,
            destinations=path_list,
        )

    def start(self, poll_interval: float = 0.5) -> None:
        """Starts background monitoring thread."""
        if self._thread is not None:
            return

        self._stop_event.clear()

        def worker():
            while not self._stop_event.is_set():
                self.sample()
                self._stop_event.wait(poll_interval)

        self._thread = threading.Thread(target=worker, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stops background thread."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="SENTRY AF_UNIX Socket Monitor (Phase 6 — sandbox network namespace)")
    parser.add_argument("pid", nargs="?", type=int, default=None,
                        help="Target sandbox PID (reads /proc/<pid>/net/unix)")
    parser.add_argument("--db", default="sentry.db", help="SQLite database path")
    parser.add_argument("--interval", type=float, default=1.0, help="Sample interval in seconds")
    parser.add_argument("--duration", type=float, default=None, help="Duration to run in seconds")
    args = parser.parse_args()

    db = SentryDB(args.db)
    monitor = NetworkMonitor(pid=args.pid, db=db)
    print(f"[NetworkMonitor] Monitoring PID {args.pid or 'Host'} AF_UNIX sockets")
    print(f"{'Time':<10} {'Active Unix':<14} {'New/min':<12} {'Socket Paths'}")
    print("─" * 70)

    start = time.time()
    try:
        while True:
            sample = monitor.sample()
            elapsed = time.time() - start
            paths_str = ", ".join(sample.destinations[:3])
            if len(sample.destinations) > 3:
                paths_str += f" (+{len(sample.destinations)-3} more)"

            print(f"{elapsed:8.1f}s  {sample.active_connections:<14} {sample.connection_rate:<12.1f} {paths_str}")
            sys.stdout.flush()

            if args.duration and elapsed >= args.duration:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[NetworkMonitor] Stopped by user.")


if __name__ == "__main__":
    main()
