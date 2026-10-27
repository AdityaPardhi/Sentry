"""
test_risk_engine.py — Unit tests for Phase 7 (Risk Scoring Engine)

Tests:
  - Step 7.1: Individual rule functions (CPU, RSS, fork bomb, mass files, net burst, seccomp)
  - Step 7.2: Composite score accumulation and clamping (0–100)
  - Step 7.3: Band classifications: NORMAL, LOW, MEDIUM, HIGH, CRITICAL
  - SQLite persistence in risk_scores table
"""

import os
import sys
import time
import json
import unittest
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.database import SentryDB
from monitor.process_monitor import ProcessSample
from monitor.risk_engine import (
    RiskEngine,
    score_to_band,
    rule_cpu_anomaly,
    rule_rss_growth,
    rule_fork_bomb,
    rule_mass_file_writes,
    rule_network_burst,
    rule_seccomp_violation
)


class TestRiskEngine(unittest.TestCase):

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.db = SentryDB(self.temp_db_path)
        self.engine = RiskEngine(pid=1234, db=self.db)

    def tearDown(self):
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.unlink(self.temp_db_path)

    def test_score_to_band(self):
        """Step 7.3: Check correct threshold boundaries for threat bands."""
        self.assertEqual(score_to_band(0), "NORMAL")
        self.assertEqual(score_to_band(20), "NORMAL")
        self.assertEqual(score_to_band(21), "LOW")
        self.assertEqual(score_to_band(40), "LOW")
        self.assertEqual(score_to_band(41), "MEDIUM")
        self.assertEqual(score_to_band(60), "MEDIUM")
        self.assertEqual(score_to_band(61), "HIGH")
        self.assertEqual(score_to_band(80), "HIGH")
        self.assertEqual(score_to_band(81), "CRITICAL")
        self.assertEqual(score_to_band(100), "CRITICAL")

    def test_baseline_normal(self):
        """Step 7.1: Quiet baseline activity produces score 0 and NORMAL band."""
        p_sample = ProcessSample(
            pid=1234,
            timestamp=time.time(),
            cpu_percent=1.5,
            rss_kb=2048,
            child_count=0,
            spawn_rate=0,
            tree={},
            is_alive=True
        )

        assessment = self.engine.evaluate(
            proc_sample=p_sample,
            file_rate=0.0,
            conn_rate=0.0,
            active_conns=0,
            seccomp_killed=False
        )

        self.assertEqual(assessment.score, 0)
        self.assertEqual(assessment.band, "NORMAL")
        self.assertEqual(len(assessment.triggered_rules), 0)

    def test_cpu_anomaly_rule(self):
        """Step 7.1: Sustained high CPU triggers CPU_ANOMALY rule."""
        p_samples = [
            ProcessSample(1234, time.time(), 92.0, 2048, 0, 0, {}, True),
            ProcessSample(1234, time.time(), 88.0, 2048, 0, 0, {}, True)
        ]
        result = rule_cpu_anomaly(p_samples)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_name, "CPU_ANOMALY")
        self.assertEqual(result.points, 25)

    def test_fork_bomb_rule(self):
        """Step 7.1: High child process count triggers FORK_BOMB_ACTIVE."""
        p_samples = [
            ProcessSample(1234, time.time(), 10.0, 4096, 25, 10, {}, True)
        ]
        result = rule_fork_bomb(p_samples)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_name, "FORK_BOMB_ACTIVE")
        self.assertEqual(result.points, 25)

    def test_mass_file_writes_rule(self):
        """Step 7.1: Burst file operations trigger MASS_FILE_BURST_CRITICAL."""
        result = rule_mass_file_writes(850.0)
        self.assertIsNotNone(result)
        self.assertEqual(result.rule_name, "MASS_FILE_BURST_CRITICAL")
        self.assertEqual(result.points, 40)

    def test_compound_threat_critical(self):
        """Step 7.2: Compounding threat signals push score into CRITICAL band."""
        p_sample = ProcessSample(
            pid=1234,
            timestamp=time.time(),
            cpu_percent=85.0,     # CPU_ANOMALY: +15
            rss_kb=300 * 1024,   # RSS_ELEVATED: +10
            child_count=15,      # FORK_BOMB_ACTIVE: +25
            spawn_rate=8,
            tree={},
            is_alive=True
        )

        # File rate 600 files/min (+40), Seccomp kill (+35)
        # Total: 15 + 10 + 25 + 40 + 35 = 125 -> clamped to 100
        assessment = self.engine.evaluate(
            proc_sample=p_sample,
            file_rate=600.0,
            conn_rate=0.0,
            active_conns=0,
            seccomp_killed=True
        )

        self.assertEqual(assessment.score, 100)
        self.assertEqual(assessment.band, "CRITICAL")
        self.assertGreaterEqual(len(assessment.triggered_rules), 4)

    def test_sqlite_persistence(self):
        """Step 7.2: Verify risk scores and explanations are saved in database."""
        p_sample = ProcessSample(1234, time.time(), 5.0, 2048, 0, 0, {}, True)
        self.engine.evaluate(p_sample, file_rate=150.0)  # +30 points -> LOW/MEDIUM

        scores = self.db.get_risk_scores(pid=1234)
        self.assertEqual(len(scores), 1)
        self.assertEqual(scores[0]["score"], 30)
        self.assertEqual(scores[0]["band"], "LOW")
        rules = json.loads(scores[0]["triggered_rules"])
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["rule_name"], "MASS_FILE_WRITES")


if __name__ == "__main__":
    unittest.main()
