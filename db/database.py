"""
Database module for SENTRY sandbox monitor.
Manages SQLite storage for metrics, samples, and incident logs.
"""

import os
import sqlite3
import time
import contextlib
from typing import List, Dict, Any, Optional

DEFAULT_DB_PATH = "sentry.db"


class SentryDB:
    """SQLite database manager for SENTRY."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._init_schema()

    @contextlib.contextmanager
    def get_connection(self):
        """Yields a SQLite connection and automatically closes it upon exit."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_schema(self) -> None:
        """Initializes tables for Phase 4 (and prepared for future phases)."""
        with self.get_connection() as conn:
            # Phase 4: Process samples table (per plan.md Step 4.4)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS process_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER NOT NULL,
                    timestamp REAL NOT NULL,
                    cpu_percent REAL NOT NULL,
                    rss_kb INTEGER NOT NULL,
                    child_count INTEGER NOT NULL,
                    spawn_rate INTEGER NOT NULL
                );
            """)

            # Index for fast queries by PID and timestamp
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_proc_samples_pid_time
                ON process_samples(pid, timestamp);
            """)

            # Phase 5: File events table (Step 5.1)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    is_dir INTEGER NOT NULL DEFAULT 0
                );
            """)

            # Phase 5: File rate samples table (Step 5.2)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER,
                    timestamp REAL NOT NULL,
                    file_write_rate REAL NOT NULL,
                    event_count INTEGER NOT NULL
                );
            """)

            # Phase 6: Network rate samples table (Step 6.1 & 6.2)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS network_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER,
                    timestamp REAL NOT NULL,
                    active_connections INTEGER NOT NULL,
                    connection_rate REAL NOT NULL,
                    syn_sent_count INTEGER NOT NULL,
                    destinations TEXT
                );
            """)

            # Phase 7: Risk assessment table (Step 7.1–7.3)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS risk_scores (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pid INTEGER,
                    timestamp REAL NOT NULL,
                    score INTEGER NOT NULL,
                    band TEXT NOT NULL,
                    triggered_rules TEXT NOT NULL
                );
            """)

            # Phase 8, 9 & 10: Consolidated Forensic Incidents Table (Step 10.1)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    id INTEGER,
                    pid INTEGER NOT NULL,
                    executable TEXT DEFAULT 'unknown',
                    start_time TEXT NOT NULL,
                    detection_time TEXT NOT NULL,
                    cpu_percent REAL DEFAULT 0.0,
                    rss_kb INTEGER DEFAULT 0,
                    child_count INTEGER DEFAULT 0,
                    file_write_rate REAL DEFAULT 0.0,
                    connection_attempts INTEGER DEFAULT 0,
                    risk_score INTEGER NOT NULL,
                    risk_band TEXT NOT NULL,
                    score INTEGER,
                    band TEXT,
                    action_taken TEXT NOT NULL,
                    details TEXT DEFAULT '',
                    pre_metric REAL DEFAULT 0.0,
                    post_metric REAL DEFAULT 0.0,
                    recheck_metric REAL DEFAULT 0.0,
                    resolution TEXT DEFAULT 'PENDING'
                );
            """)

            conn.commit()

    def insert_process_sample(
        self,
        pid: int,
        timestamp: float,
        cpu_percent: float,
        rss_kb: int,
        child_count: int,
        spawn_rate: int
    ) -> int:
        """Inserts one process sample record (Step 4.4)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO process_samples (pid, timestamp, cpu_percent, rss_kb, child_count, spawn_rate)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (pid, timestamp, round(cpu_percent, 2), rss_kb, child_count, spawn_rate)
            )
            conn.commit()
            return cursor.lastrowid

    def insert_file_event(
        self,
        timestamp: float,
        event_type: str,
        path: str,
        is_dir: int = 0
    ) -> int:
        """Inserts one raw file event (Step 5.1)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO file_events (timestamp, event_type, path, is_dir)
                VALUES (?, ?, ?, ?);
                """,
                (timestamp, event_type, path, is_dir)
            )
            conn.commit()
            return cursor.lastrowid

    def insert_file_sample(
        self,
        timestamp: float,
        file_write_rate: float,
        event_count: int,
        pid: Optional[int] = None
    ) -> int:
        """Inserts one file rate sample (Step 5.2)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO file_samples (pid, timestamp, file_write_rate, event_count)
                VALUES (?, ?, ?, ?);
                """,
                (pid, timestamp, round(file_write_rate, 2), event_count)
            )
            conn.commit()
            return cursor.lastrowid

    def get_process_samples(self, pid: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves process samples, optionally filtered by PID."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if pid is not None:
                cursor.execute(
                    """
                    SELECT id, pid, timestamp, cpu_percent, rss_kb, child_count, spawn_rate
                    FROM process_samples
                    WHERE pid = ?
                    ORDER BY id ASC
                    LIMIT ?;
                    """,
                    (pid, limit)
                )
            else:
                cursor.execute(
                    """
                    SELECT id, pid, timestamp, cpu_percent, rss_kb, child_count, spawn_rate
                    FROM process_samples
                    ORDER BY id ASC
                    LIMIT ?;
                    """,
                    (limit,)
                )
            results = []
            for row in cursor.fetchall():
                d = dict(row)
                if "timestamp" not in d or d["timestamp"] is None:
                    dt_str = d.get("detection_time") or d.get("start_time")
                    ts = None
                    if dt_str:
                        try:
                            ts = time.mktime(time.strptime(dt_str, "%Y-%m-%d %H:%M:%S"))
                        except Exception:
                            pass
                    d["timestamp"] = ts if ts is not None else time.time()
                results.append(d)
            return results

    def get_file_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves raw file events."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, timestamp, event_type, path, is_dir
                FROM file_events
                ORDER BY id ASC
                LIMIT ?;
                """,
                (limit,)
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_file_samples(self, pid: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves file rate samples."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if pid is not None:
                cursor.execute(
                    """
                    SELECT id, pid, timestamp, file_write_rate, event_count
                    FROM file_samples
                    WHERE pid = ?
                    ORDER BY id ASC
                    LIMIT ?;
                    """,
                    (pid, limit)
                )
            else:
                cursor.execute(
                    """
                    SELECT id, pid, timestamp, file_write_rate, event_count
                    FROM file_samples
                    ORDER BY id ASC
                    LIMIT ?;
                    """,
                    (limit,)
                )
            return [dict(row) for row in cursor.fetchall()]

    def insert_network_sample(
        self,
        timestamp: float,
        active_connections: int,
        connection_rate: float,
        syn_sent_count: int,
        destinations: str = "[]",
        pid: Optional[int] = None
    ) -> int:
        """Inserts one network activity sample (Phase 6)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO network_samples (pid, timestamp, active_connections, connection_rate, syn_sent_count, destinations)
                VALUES (?, ?, ?, ?, ?, ?);
                """,
                (pid, timestamp, active_connections, round(connection_rate, 2), syn_sent_count, destinations)
            )
            conn.commit()
            return cursor.lastrowid

    def get_network_samples(self, pid: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves network activity samples."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if pid is not None:
                cursor.execute(
                    """
                    SELECT id, pid, timestamp, active_connections, connection_rate, syn_sent_count, destinations
                    FROM network_samples
                    WHERE pid = ?
                    ORDER BY id ASC
                    LIMIT ?;
                    """,
                    (pid, limit)
                )
            else:
                cursor.execute(
                    """
                    SELECT id, pid, timestamp, active_connections, connection_rate, syn_sent_count, destinations
                    FROM network_samples
                    ORDER BY id ASC
                    LIMIT ?;
                    """,
                    (limit,)
                )
            return [dict(row) for row in cursor.fetchall()]

    def insert_risk_score(
        self,
        timestamp: float,
        score: int,
        band: str,
        triggered_rules: str = "[]",
        pid: Optional[int] = None
    ) -> int:
        """Inserts one risk assessment score record (Phase 7)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO risk_scores (pid, timestamp, score, band, triggered_rules)
                VALUES (?, ?, ?, ?, ?);
                """,
                (pid, timestamp, score, band, triggered_rules)
            )
            conn.commit()
            return cursor.lastrowid

    def get_risk_scores(self, pid: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves risk assessment records."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if pid is not None:
                cursor.execute(
                    """
                    SELECT id, pid, timestamp, score, band, triggered_rules
                    FROM risk_scores
                    WHERE pid = ?
                    ORDER BY id ASC
                    LIMIT ?;
                    """,
                    (pid, limit)
                )
            else:
                cursor.execute(
                    """
                    SELECT id, pid, timestamp, score, band, triggered_rules
                    FROM risk_scores
                    ORDER BY id ASC
                    LIMIT ?;
                    """,
                    (limit,)
                )
            return [dict(row) for row in cursor.fetchall()]

    def insert_incident(
        self,
        pid: int,
        timestamp: float,
        score: int,
        band: str,
        action_taken: str,
        details: str = "",
        pre_metric: float = 0.0,
        post_metric: float = 0.0,
        resolution: str = "PENDING",
        executable: str = "unknown",
        start_time: Optional[str] = None,
        detection_time: Optional[str] = None,
        cpu_percent: float = 0.0,
        rss_kb: int = 0,
        child_count: int = 0,
        file_write_rate: float = 0.0,
        connection_attempts: int = 0
    ) -> int:
        """Inserts an incident mitigation record (Phase 8, 9 & 10)."""
        det_time_str = detection_time or time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        st_time_str = start_time or det_time_str
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO incidents (
                    pid, executable, start_time, detection_time,
                    cpu_percent, rss_kb, child_count, file_write_rate, connection_attempts,
                    risk_score, risk_band, score, band, action_taken, details,
                    pre_metric, post_metric, recheck_metric, resolution
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    pid, executable, st_time_str, det_time_str,
                    round(cpu_percent, 1), rss_kb, child_count, round(file_write_rate, 1), connection_attempts,
                    score, band, score, band, action_taken, details,
                    round(pre_metric, 2), round(post_metric, 2), round(post_metric, 2), resolution
                )
            )
            # Sync alias id column
            last_id = cursor.lastrowid
            cursor.execute("UPDATE incidents SET id = incident_id WHERE incident_id = ?;", (last_id,))
            conn.commit()
            return last_id

    def update_incident_resolution(
        self,
        incident_id: int,
        post_metric: float,
        resolution: str,
        details: Optional[str] = None
    ) -> None:
        """Updates resolution status and post-action verification metrics (Phase 9 & 10)."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if details:
                cursor.execute(
                    """
                    UPDATE incidents
                    SET post_metric = ?, recheck_metric = ?, resolution = ?, details = details || ' | ' || ?
                    WHERE incident_id = ? OR id = ?;
                    """,
                    (round(post_metric, 2), round(post_metric, 2), resolution, details, incident_id, incident_id)
                )
            else:
                cursor.execute(
                    """
                    UPDATE incidents
                    SET post_metric = ?, recheck_metric = ?, resolution = ?
                    WHERE incident_id = ? OR id = ?;
                    """,
                    (round(post_metric, 2), round(post_metric, 2), resolution, incident_id, incident_id)
                )
            conn.commit()

    def get_incidents(self, pid: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Retrieves consolidated incident records."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if pid is not None:
                cursor.execute(
                    """
                    SELECT incident_id, id, pid, executable, start_time, detection_time,
                           cpu_percent, rss_kb, child_count, file_write_rate, connection_attempts,
                           risk_score, risk_band, score, band, action_taken, details,
                           pre_metric, post_metric, recheck_metric, resolution
                    FROM incidents
                    WHERE pid = ?
                    ORDER BY incident_id ASC
                    LIMIT ?;
                    """,
                    (pid, limit)
                )
            else:
                cursor.execute(
                    """
                    SELECT incident_id, id, pid, executable, start_time, detection_time,
                           cpu_percent, rss_kb, child_count, file_write_rate, connection_attempts,
                           risk_score, risk_band, score, band, action_taken, details,
                           pre_metric, post_metric, recheck_metric, resolution
                    FROM incidents
                    ORDER BY incident_id ASC
                    LIMIT ?;
                    """,
                    (limit,)
                )
            return [dict(row) for row in cursor.fetchall()]

    def clear(self) -> None:
        """Clears all records (useful for test runs)."""
        with self.get_connection() as conn:
            conn.execute("DELETE FROM process_samples;")
            conn.execute("DELETE FROM file_events;")
            conn.execute("DELETE FROM file_samples;")
            conn.execute("DELETE FROM network_samples;")
            conn.execute("DELETE FROM risk_scores;")
            conn.execute("DELETE FROM incidents;")
            conn.commit()


if __name__ == "__main__":
    import sys
    db_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DB_PATH
    db = SentryDB(db_path)
    samples = db.get_process_samples(limit=50)
    print(f"SENTRY Database: {db_path} ({len(samples)} samples)")
    print("=" * 80)
    print(f"{'ID':<6} {'PID':<8} {'Time':<20} {'CPU %':<10} {'RSS (KB)':<12} {'Children':<10} {'Spawn Rate':<10}")
    print("-" * 80)
    for s in samples:
        t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s["timestamp"]))
        print(f"{s['id']:<6} {s['pid']:<8} {t_str:<20} {s['cpu_percent']:<10.1f} {s['rss_kb']:<12} {s['child_count']:<10} {s['spawn_rate']:<10}")
