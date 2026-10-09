"""
response_engine.py — Automatic Incident Mitigation Engine

Simplified per changes.md Part 2:
  The full escalation state machine has been replaced with a straightforward
  3-step response sequence applied to every violation count threshold:

    1. Throttle (3 violations)  → halve CPU quota (cpu.max)
    2. SIGKILL                  → kill the sandboxed process
    3. Cgroup freeze            → write "1" to cgroup.freeze
    4. Log                      → record incident to SQLite

  No further escalation or recovery loop is performed.  The old
  PENDING → RECOVERED / STILL_HIGH → ESCALATED state machine is removed.
"""

import os
import sys
import time
import signal
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

SIGKILL = getattr(signal, "SIGKILL", 9)

# Allow importing SentryDB and RiskAssessment
try:
    from db.database import SentryDB
    from monitor.risk_engine import RiskAssessment
except ImportError:
    try:
        from sentry.db.database import SentryDB
        from sentry.monitor.risk_engine import RiskAssessment
    except ImportError:
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from db.database import SentryDB
        from monitor.risk_engine import RiskAssessment


@dataclass
class Incident:
    pid: int
    timestamp: float
    score: int
    band: str
    action_taken: str
    details: str
    id: Optional[int] = None
    pre_metric: float = 0.0
    post_metric: float = 0.0
    resolution: str = "TERMINATED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ResponseEngine:
    """
    Executes tiered automated responses based on violation count.

    Response sequence (applied in order, once each threshold is reached):
      1. After THROTTLE_VIOLATIONS violations → throttle CPU (halve cpu.max)
      2. After KILL_VIOLATIONS    violations → SIGKILL the process
      3. After FREEZE_VIOLATIONS  violations → freeze the cgroup
      All actions are logged to the SQLite incidents table.
    """

    THROTTLE_MAX_VIOLATIONS = 3

    def __init__(
        self,
        db: Optional[SentryDB] = None,
        cgroup_path: str = "/sys/fs/cgroup/sentry_sandbox"
    ):
        self.db = db
        self.cgroup_path = cgroup_path
        self.incidents: List[Incident] = []
        self._violation_count: int = 0
        self._killed: bool = False
        self._frozen: bool = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_cgroup_path(self, pid: Optional[int] = None) -> str:
        """Returns the active cgroup directory for the process."""
        if os.path.exists(self.cgroup_path):
            return self.cgroup_path
        if pid:
            dyn_path = f"/sys/fs/cgroup/sentry_{pid}"
            if os.path.exists(dyn_path):
                return dyn_path
        return self.cgroup_path

    def _read_cpu_max(self, pid: Optional[int] = None):
        """Reads current cpu.max (quota, period). Returns (None, period) if max."""
        cg_dir = self._get_cgroup_path(pid)
        path = os.path.join(cg_dir, "cpu.max")
        if not os.path.exists(path):
            return None, 100000
        try:
            with open(path, "r") as f:
                parts = f.read().strip().split()
                if len(parts) >= 2:
                    quota = int(parts[0]) if parts[0] != "max" else None
                    period = int(parts[1])
                    return quota, period
        except Exception:
            pass
        return None, 100000

    def _write_cpu_max(self, quota: int, period: int = 100000, pid: Optional[int] = None) -> bool:
        """Writes quota and period to cgroup v2 cpu.max."""
        cg_dir = self._get_cgroup_path(pid)
        path = os.path.join(cg_dir, "cpu.max")
        if not os.path.exists(path):
            return False
        try:
            with open(path, "w") as f:
                f.write(f"{quota} {period}\n")
            return True
        except (PermissionError, OSError):
            return False

    def _freeze_cgroup(self, pid: Optional[int] = None) -> bool:
        """Freezes the cgroup by writing 1 to cgroup.freeze."""
        cg_dir = self._get_cgroup_path(pid)
        path = os.path.join(cg_dir, "cgroup.freeze")
        if not os.path.exists(path):
            return False
        try:
            with open(path, "w") as f:
                f.write("1\n")
            return True
        except (PermissionError, OSError):
            return False

    def _log_incident(
        self,
        pid: int,
        score: int,
        band: str,
        action: str,
        details: str,
        pre_metric: float,
        executable: str = "unknown",
        cpu_percent: float = 0.0,
        rss_kb: int = 0,
        child_count: int = 0,
        file_write_rate: float = 0.0,
        connection_attempts: int = 0,
    ) -> Incident:
        now = time.time()
        incident = Incident(
            pid=pid,
            timestamp=now,
            score=score,
            band=band,
            action_taken=action,
            details=details,
            pre_metric=pre_metric,
            resolution="TERMINATED" if "SIGKILL" in action else "THROTTLED",
        )
        if self.db is not None:
            try:
                inc_id = self.db.insert_incident(
                    pid=incident.pid,
                    timestamp=incident.timestamp,
                    score=incident.score,
                    band=incident.band,
                    action_taken=incident.action_taken,
                    details=incident.details,
                    pre_metric=incident.pre_metric,
                    post_metric=0.0,
                    resolution=incident.resolution,
                    executable=executable,
                    cpu_percent=cpu_percent,
                    rss_kb=rss_kb,
                    child_count=child_count,
                    file_write_rate=file_write_rate,
                    connection_attempts=connection_attempts,
                )
                incident.id = inc_id
            except Exception as e:
                print(f"[ResponseEngine ERROR] insert_incident failed: {e}", file=sys.stderr)
        self.incidents.append(incident)
        return incident

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def act(
        self,
        assessment: RiskAssessment,
        target_pid: Optional[int] = None,
        pre_metric: float = 0.0,
        executable: str = "unknown",
        cpu_percent: float = 0.0,
        rss_kb: int = 0,
        child_count: int = 0,
        file_write_rate: float = 0.0,
        connection_attempts: int = 0,
    ) -> Optional[Incident]:
        """
        Applies response sequence per changes.md Part 2:
          throttle 3 violations → SIGKILL → cgroup freeze → log. Nothing more.

          - Violations 1..3 : Throttle CPU quota (halve cpu.max) and log.
          - Violations > 3  : Send SIGKILL to process, freeze cgroup, and log.
        """
        pid = target_pid if target_pid is not None else assessment.pid
        if not pid:
            return None

        if assessment.band == "NORMAL":
            return None

        self._violation_count += 1
        incident: Optional[Incident] = None

        if self._violation_count <= self.THROTTLE_MAX_VIOLATIONS:
            # 1. Throttle CPU quota
            curr_quota, period = self._read_cpu_max(pid)
            new_quota = max(2000, curr_quota // 2) if curr_quota else 20000
            success = self._write_cpu_max(new_quota, period, pid)
            details = (
                f"Violation {self._violation_count}/3: Halved CPU quota {curr_quota} → {new_quota} (period {period})"
                if success else f"Violation {self._violation_count}/3: Failed to adjust cpu.max"
            )
            print(f"[ResponseEngine] THROTTLE: {details}", file=sys.stderr)
            incident = self._log_incident(
                pid, assessment.score, assessment.band,
                "THROTTLE_CPU", details, pre_metric,
                executable, cpu_percent, rss_kb, child_count,
                file_write_rate, connection_attempts,
            )
        else:
            # 2. Exceeded 3 violations: SIGKILL → cgroup freeze → log
            if not self._killed:
                self._killed = True
                try:
                    os.kill(pid, SIGKILL)
                    kill_msg = f"Sent SIGKILL to PID {pid} (score={assessment.score})"
                except ProcessLookupError:
                    kill_msg = f"SIGKILL to PID {pid}: process already exited"
                except PermissionError as e:
                    kill_msg = f"SIGKILL to PID {pid}: PermissionError {e}"
                except Exception as e:
                    kill_msg = f"SIGKILL to PID {pid}: {e}"

                # 3. Cgroup freeze
                self._frozen = self._freeze_cgroup(pid)
                cg_path = self._get_cgroup_path(pid)
                freeze_msg = f"Froze cgroup {cg_path}" if self._frozen else f"Failed to freeze cgroup {cg_path}"

                details = f"Violation {self._violation_count} (>3): {kill_msg}; {freeze_msg}"
                print(f"[ResponseEngine] KILL+FREEZE: {details}", file=sys.stderr)

                # 4. Log
                incident = self._log_incident(
                    pid, assessment.score, assessment.band,
                    "SIGKILL_FREEZE", details, pre_metric,
                    executable, cpu_percent, rss_kb, child_count,
                    file_write_rate, connection_attempts,
                )

        return incident
