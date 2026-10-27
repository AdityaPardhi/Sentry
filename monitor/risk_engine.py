"""
risk_engine.py — Phase 7: Risk Scoring Engine

Evaluates real-time telemetry from ProcessMonitor, FileMonitor, and NetworkMonitor
against explainable, point-based heuristic rules:
  - Step 7.1: Modular, pure rule functions assessing CPU, RSS, fork rate, file I/O, network, and seccomp.
  - Step 7.2: Sums points into a single composite score (0–100) on each sampling tick.
  - Step 7.3: Categorizes risk score into explainable bands:
              0–20: NORMAL | 21–40: LOW | 41–60: MEDIUM | 61–80: HIGH | 81–100: CRITICAL
  - Logs results to SQLite risk_scores table with full rule traceability.
"""

import os
import sys
import time
import json
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict

# Allow importing SentryDB and ProcessSample
try:
    from db.database import SentryDB
    from monitor.process_monitor import ProcessSample
except ImportError:
    try:
        from sentry.db.database import SentryDB
        from sentry.monitor.process_monitor import ProcessSample
    except ImportError:
        sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from db.database import SentryDB
        from monitor.process_monitor import ProcessSample


@dataclass
class RuleResult:
    rule_name: str
    points: int
    reason: str


@dataclass
class RiskAssessment:
    pid: Optional[int]
    timestamp: float
    score: int
    band: str
    triggered_rules: List[RuleResult]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "timestamp": self.timestamp,
            "score": self.score,
            "band": self.band,
            "triggered_rules": [asdict(r) for r in self.triggered_rules]
        }


# ── Step 7.1: Explainable Rule Functions ──────────────────────────────────

def rule_cpu_anomaly(proc_samples: List[ProcessSample]) -> Optional[RuleResult]:
    """
    Checks for sustained or spike CPU usage anomalies.
    Rule: CPU > 70% in recent samples (+15 points).
    """
    if not proc_samples:
        return None

    recent = proc_samples[-3:]
    avg_cpu = sum(s.cpu_percent for s in recent) / len(recent)
    max_cpu = max(s.cpu_percent for s in recent)

    if max_cpu >= 80.0 or avg_cpu >= 60.0:
        return RuleResult(
            rule_name="CPU_ANOMALY",
            points=25,
            reason=f"Sustained high CPU usage (peak: {max_cpu:.1f}%, avg: {avg_cpu:.1f}%)"
        )
    elif max_cpu >= 35.0 or avg_cpu >= 30.0:
        return RuleResult(
            rule_name="CPU_ANOMALY",
            points=25,
            reason=f"Cgroup quota saturated CPU usage (peak: {max_cpu:.1f}%, avg: {avg_cpu:.1f}%)"
        )
    return None


def rule_rss_growth(proc_samples: List[ProcessSample]) -> Optional[RuleResult]:
    """
    Checks for rapid memory allocation or memory exhaustion.
    Rule: RSS grew by > 20 MB across samples or exceeds 250 MB (+15 points).
    """
    if len(proc_samples) < 2:
        if proc_samples and proc_samples[-1].rss_kb > 250 * 1024:
            return RuleResult(
                rule_name="RSS_ELEVATED",
                points=10,
                reason=f"High memory consumption ({proc_samples[-1].rss_kb / 1024:.1f} MB)"
            )
        return None

    first = proc_samples[0].rss_kb
    last = proc_samples[-1].rss_kb
    delta_mb = (last - first) / 1024.0

    if delta_mb >= 20.0 or (last / 1024.0) >= 250.0:
        return RuleResult(
            rule_name="RSS_GROWTH",
            points=15,
            reason=f"Rapid memory expansion (+{delta_mb:.1f} MB, total: {last / 1024.0:.1f} MB)"
        )
    return None


def rule_fork_bomb(proc_samples: List[ProcessSample]) -> Optional[RuleResult]:
    """
    Detects process replication or fork-bomb attempts.
    Rule: Child process count > 10 (+25 points) or spawn rate > 4/interval (+20 points).
    """
    if not proc_samples:
        return None

    last = proc_samples[-1]
    if last.child_count >= 10:
        return RuleResult(
            rule_name="FORK_BOMB_ACTIVE",
            points=25,
            reason=f"Severe process multiplication ({last.child_count} active children)"
        )
    elif last.spawn_rate >= 4:
        return RuleResult(
            rule_name="FORK_BURST",
            points=20,
            reason=f"Rapid process spawning ({last.spawn_rate} new processes in interval)"
        )
    return None


def rule_mass_file_writes(file_rate: float) -> Optional[RuleResult]:
    """
    Detects ransomware or wiper-like burst file modifications.
    Rule:
      - Rate > 500 files/min: +40 points (Critical threat)
      - Rate > 100 files/min: +30 points (High threat)
      - Rate > 20 files/min:  +15 points (Elevated file rate)
    """
    if file_rate >= 500.0:
        return RuleResult(
            rule_name="MASS_FILE_BURST_CRITICAL",
            points=40,
            reason=f"Extreme mass file modification/deletion ({file_rate:.1f} files/min)"
        )
    elif file_rate >= 100.0:
        return RuleResult(
            rule_name="MASS_FILE_WRITES",
            points=30,
            reason=f"Elevated mass file activity ({file_rate:.1f} files/min)"
        )
    elif file_rate >= 20.0:
        return RuleResult(
            rule_name="FILE_RATE_ELEVATED",
            points=15,
            reason=f"Moderate file creation rate ({file_rate:.1f} files/min)"
        )
    return None


def rule_network_burst(conn_rate: float, active_conns: int) -> Optional[RuleResult]:
    """
    Detects port scanning, botnet beaconing, or C2 connection spamming.
    Rule:
      - Rate > 30 conn/min: +25 points
      - Rate > 10 conn/min: +15 points
    """
    if conn_rate >= 30.0 or active_conns >= 15:
        return RuleResult(
            rule_name="NET_SCAN_BURST",
            points=25,
            reason=f"Aggressive connection attempts ({conn_rate:.1f} conn/min, {active_conns} active)"
        )
    elif conn_rate >= 10.0 or active_conns >= 5:
        return RuleResult(
            rule_name="NET_RATE_ELEVATED",
            points=15,
            reason=f"Elevated network connection attempts ({conn_rate:.1f} conn/min)"
        )
    return None


def rule_seccomp_violation(seccomp_killed: bool) -> Optional[RuleResult]:
    """
    Detects violation of restricted kernel syscall attack surface.
    Rule: Any blocked syscall hitting SIGSYS (+35 points).
    """
    if seccomp_killed:
        return RuleResult(
            rule_name="SECCOMP_SIGSYS",
            points=35,
            reason="Illegal restricted syscall attempted (SIGSYS seccomp filter kill)"
        )
    return None


# Step 7.3: Score Band Mapping

def score_to_band(score: int) -> str:
    """
    Maps numerical score to SENTRY threat band:
      0–20  : NORMAL
      21–40 : LOW
      41–60 : MEDIUM
      61–80 : HIGH
      81+   : CRITICAL
    """
    if score <= 20:
        return "NORMAL"
    elif score <= 40:
        return "LOW"
    elif score <= 60:
        return "MEDIUM"
    elif score <= 80:
        return "HIGH"
    else:
        return "CRITICAL"


# Step 7.2: RiskEngine Core

class RiskEngine:
    """
    Evaluates real-time telemetry from all monitoring sources and computes
    explainable composite risk scores.
    """

    def __init__(self, pid: Optional[int] = None, db: Optional[SentryDB] = None):
        self.pid = pid
        self.db = db
        self.proc_samples: List[ProcessSample] = []
        self.latest_assessment: Optional[RiskAssessment] = None

    def add_process_sample(self, sample: ProcessSample) -> None:
        """Stores process sample in rolling history buffer."""
        self.proc_samples.append(sample)
        if len(self.proc_samples) > 20:
            self.proc_samples.pop(0)

    def evaluate(
        self,
        proc_sample: Optional[ProcessSample] = None,
        file_rate: float = 0.0,
        conn_rate: float = 0.0,
        active_conns: int = 0,
        seccomp_killed: bool = False
    ) -> RiskAssessment:
        """
        Runs all heuristic rules, aggregates score, classifies band,
        and logs to SQLite.
        """
        now = time.time()
        if proc_sample:
            self.add_process_sample(proc_sample)

        triggered_rules: List[RuleResult] = []

        # 1. CPU Rule
        r_cpu = rule_cpu_anomaly(self.proc_samples)
        if r_cpu: triggered_rules.append(r_cpu)

        # 2. Memory Rule
        r_rss = rule_rss_growth(self.proc_samples)
        if r_rss: triggered_rules.append(r_rss)

        # 3. Fork Rule
        r_fork = rule_fork_bomb(self.proc_samples)
        if r_fork: triggered_rules.append(r_fork)

        # 4. File Rate Rule
        r_file = rule_mass_file_writes(file_rate)
        if r_file: triggered_rules.append(r_file)

        # 5. Network Rule
        r_net = rule_network_burst(conn_rate, active_conns)
        if r_net: triggered_rules.append(r_net)

        # 6. Seccomp Violation Rule
        r_sec = rule_seccomp_violation(seccomp_killed)
        if r_sec: triggered_rules.append(r_sec)

        # Calculate total score clamped to [0, 100]
        raw_score = sum(r.points for r in triggered_rules)
        total_score = min(100, max(0, raw_score))
        band = score_to_band(total_score)

        assessment = RiskAssessment(
            pid=self.pid,
            timestamp=now,
            score=total_score,
            band=band,
            triggered_rules=triggered_rules
        )
        self.latest_assessment = assessment

        # Persist to SQLite risk_scores table
        if self.db is not None:
            try:
                self.db.insert_risk_score(
                    timestamp=now,
                    score=total_score,
                    band=band,
                    triggered_rules=json.dumps([asdict(r) for r in triggered_rules]),
                    pid=self.pid
                )
            except Exception as e:
                print(f"[RiskEngine ERROR] insert_risk_score failed: {e}", file=sys.stderr)

        return assessment
