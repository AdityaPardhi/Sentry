"""
file_monitor.py — Phase 5: File Behavior Monitor

Monitors file operations within the sandbox filesystem using Linux inotify:
  - Step 5.1: Watches file creates, modifies, deletes, and renames recursively
              (IN_CREATE, IN_MODIFY, IN_DELETE, IN_MOVED_FROM, IN_MOVED_TO).
  - Step 5.2: Computes a rolling files-per-minute rate using a sliding 60-second window.
  - Logs raw events to file_events and rate samples to file_samples in SQLite.

Uses pure Python ctypes to call Linux inotify syscalls — zero external pip dependencies.
"""

import os
import sys
import time
import errno
import ctypes
import select
import struct
import threading
from collections import deque
from typing import Dict, List, Optional, Tuple, Deque
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


# ── inotify ctypes declarations ──────────────────────────────────────────

try:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    # inotify syscall signatures
    libc.inotify_init1.argtypes = [ctypes.c_int]
    libc.inotify_init1.restype = ctypes.c_int

    libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    libc.inotify_add_watch.restype = ctypes.c_int

    libc.inotify_rm_watch.argtypes = [ctypes.c_int, ctypes.c_int]
    libc.inotify_rm_watch.restype = ctypes.c_int
except OSError:
    libc = None
IN_CLOEXEC = 0x00080000
IN_NONBLOCK = 0x00000800
IN_MODIFY = 0x00000002
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_FROM = 0x00000040
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_DELETE = 0x00000200
IN_DELETE_SELF = 0x00000400
IN_MOVE_SELF = 0x00000800
IN_ISDIR = 0x40000000
IN_ALL_EVENTS = (IN_MODIFY | IN_CLOSE_WRITE | IN_MOVED_FROM | IN_MOVED_TO | IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MOVE_SELF)
WATCH_MASK = IN_ALL_EVENTS


@dataclass
class FileEvent:
    timestamp: float
    event_type: str
    path: str
    is_dir: bool


class FileMonitor:
    """
    Recursively monitors a directory hierarchy for file operations via inotify.
    Computes a rolling files-per-minute rate metric.
    """

    def __init__(self, root_dir: str, db: Optional[SentryDB] = None, pid: Optional[int] = None):
        self.root_dir = os.path.abspath(root_dir)
        self.db = db
        self.monitored_pid = pid

        if not os.path.exists(self.root_dir):
            raise FileNotFoundError(f"Root directory '{self.root_dir}' does not exist.")

        # Initialize inotify instance
        self.fd = libc.inotify_init1(IN_NONBLOCK | IN_CLOEXEC)
        if self.fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, f"inotify_init1 failed: {os.strerror(err)}")

        # Watch descriptor maps: wd -> path, path -> wd
        self.wd_to_path: Dict[int, str] = {}
        self.path_to_wd: Dict[str, int] = {}

        # Sliding window of event timestamps for files/minute rate (Step 5.2)
        self.event_timestamps: Deque[float] = deque()
        self.start_time = time.time()
        self.total_event_count = 0

        # Background thread control
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Add initial recursive watches
        self._add_watch_recursive(self.root_dir)

    def _add_watch(self, path: str) -> Optional[int]:
        """Adds an inotify watch on a single directory."""
        if path in self.path_to_wd:
            return self.path_to_wd[path]

        b_path = path.encode("utf-8")
        wd = libc.inotify_add_watch(self.fd, b_path, WATCH_MASK)
        if wd < 0:
            return None

        self.wd_to_path[wd] = path
        self.path_to_wd[path] = wd
        return wd

    def _rm_watch(self, wd: int) -> None:
        """Removes a watch descriptor."""
        path = self.wd_to_path.pop(wd, None)
        if path:
            self.path_to_wd.pop(path, None)
        libc.inotify_rm_watch(self.fd, wd)

    def _add_watch_recursive(self, root: str) -> int:
        """Recursively watches `root` and all subdirectories."""
        count = 0
        try:
            for dirpath, dirnames, _ in os.walk(root):
                if self._add_watch(dirpath) is not None:
                    count += 1
        except (PermissionError, FileNotFoundError):
            pass
        return count

    def poll_events(self) -> List[FileEvent]:
        """
        Non-blocking read of inotify events from kernel buffer.
        Dispatches newly created directories into the watch table.
        """
        events: List[FileEvent] = []

        HEADER_SIZE = 16
        now = time.time()

        while True:
            r, _, _ = select.select([self.fd], [], [], 0)
            if not r:
                break

            try:
                data = os.read(self.fd, 65536)
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                raise

            if not data:
                break

            offset = 0
            while offset + HEADER_SIZE <= len(data):
                wd, mask, cookie, length = struct.unpack_from("iIII", data, offset)
                offset += HEADER_SIZE

                name = ""
                if length > 0 and offset + length <= len(data):
                    raw_name = data[offset:offset + length]
                    name = raw_name.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
                    offset += length

                parent_path = self.wd_to_path.get(wd, "")
                full_path = os.path.join(parent_path, name) if name else parent_path
                is_dir = bool(mask & IN_ISDIR)

                # Determine human-readable event type
                event_type = "UNKNOWN"
                if mask & IN_CREATE:
                    event_type = "CREATE"
                    if is_dir:
                        # Dynamically watch newly created subdirectory
                        self._add_watch_recursive(full_path)
                elif mask & IN_DELETE:
                    event_type = "DELETE"
                elif mask & (IN_MODIFY | IN_CLOSE_WRITE):
                    event_type = "MODIFY"
                elif mask & IN_MOVED_FROM:
                    event_type = "MOVED_FROM"
                elif mask & IN_MOVED_TO:
                    event_type = "MOVED_TO"
                    if is_dir:
                        self._add_watch_recursive(full_path)

                if event_type != "UNKNOWN":
                    fe = FileEvent(
                        timestamp=now,
                        event_type=event_type,
                        path=full_path,
                        is_dir=is_dir
                    )
                    events.append(fe)

                    with self._lock:
                        self.event_timestamps.append(now)
                        self.total_event_count += 1

                    # Log raw event to SQLite (Step 5.1)
                    if self.db is not None:
                        try:
                            self.db.insert_file_event(
                                timestamp=now,
                                event_type=event_type,
                                path=full_path,
                                is_dir=1 if is_dir else 0
                            )
                        except Exception:
                            pass

        return events

    def get_rate(self) -> float:
        """
        Computes the files-per-minute rate using a rolling 60-second window (Step 5.2).
        Prunes timestamps older than 60 seconds.
        """
        now = time.time()
        cutoff = now - 60.0

        with self._lock:
            # Prune events older than 60s
            while self.event_timestamps and self.event_timestamps[0] < cutoff:
                self.event_timestamps.popleft()

            count = len(self.event_timestamps)
            elapsed = now - self.start_time

        if elapsed < 60.0 and elapsed > 0.5:
            # Extrapolate rate if running for less than 1 minute
            return (count / elapsed) * 60.0
        return float(count)

    def sample(self) -> Tuple[float, int]:
        """
        Takes a rate sample: polls pending events, computes current files/min,
        and logs to the database.
        Returns (files_per_min, total_events_seen).
        """
        self.poll_events()
        rate = self.get_rate()
        with self._lock:
            total = self.total_event_count

        if self.db is not None:
            try:
                self.db.insert_file_sample(
                    timestamp=time.time(),
                    file_write_rate=rate,
                    event_count=total,
                    pid=self.monitored_pid
                )
            except Exception as e:
                print(f"[FileMonitor ERROR] insert_file_sample failed: {e}", file=sys.stderr)

        return rate, total

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
        """Stops background thread and releases inotify file descriptor."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._thread = None

        if self.fd >= 0:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = -1


def main():
    import argparse
    parser = argparse.ArgumentParser(description="SENTRY File Behavior Monitor (Phase 5)")
    parser.add_argument("dir", nargs="?", default="/opt/sentry/sandbox-root",
                        help="Root directory to watch recursively (default: /opt/sentry/sandbox-root)")
    parser.add_argument("--db", default="sentry.db", help="SQLite database path")
    parser.add_argument("--interval", type=float, default=1.0, help="Sample interval in seconds")
    parser.add_argument("--duration", type=float, default=None, help="Duration to run in seconds")
    args = parser.parse_args()

    db = SentryDB(args.db)
    monitor = FileMonitor(root_dir=args.dir, db=db)
    print(f"[FileMonitor] Watching '{args.dir}' recursively (inotify active)")
    print(f"{'Time':<10} {'Files/min Rate':<16} {'Total Events':<14} {'Recent Event'}")
    print("─" * 70)

    start = time.time()
    try:
        while True:
            events = monitor.poll_events()
            rate = monitor.get_rate()
            elapsed = time.time() - start

            recent_desc = ""
            if events:
                last = events[-1]
                recent_desc = f"{last.event_type} {os.path.basename(last.path)}"

            print(f"{elapsed:8.1f}s  {rate:14.1f}  {monitor.total_event_count:<14} {recent_desc}")
            sys.stdout.flush()

            if args.duration and elapsed >= args.duration:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n[FileMonitor] Stopped by user.")
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()
