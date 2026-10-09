"""
test_response_engine.py — Unit tests for Response Engine (changes.md Part 2)

Tests:
  - NORMAL band: no action taken
  - Violations 1..3: throttle CPU quota (halve cpu.max) and log incident
  - Violation 4 (>3): send SIGKILL, freeze cgroup, and log incident
"""

import os
import sys
import time
import signal
import unittest
import tempfile
from unittest.mock import patch

SIGKILL = getattr(signal, "SIGKILL", 9)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.database import SentryDB
from monitor.risk_engine import RiskAssessment, RuleResult
from monitor.response_engine import ResponseEngine, Incident


class TestResponseEngine(unittest.TestCase):

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.db = SentryDB(self.temp_db_path)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cgroup_dir = self.temp_dir.name

        # Create dummy cpu.max and cgroup.freeze
        self.cpu_max_path = os.path.join(self.cgroup_dir, "cpu.max")
        with open(self.cpu_max_path, "w") as f:
            f.write("40000 100000\n")

        self.freeze_path = os.path.join(self.cgroup_dir, "cgroup.freeze")
        with open(self.freeze_path, "w") as f:
            f.write("0\n")

        self.engine = ResponseEngine(db=self.db, cgroup_path=self.cgroup_dir)

    def tearDown(self):
        self.temp_dir.cleanup()
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.unlink(self.temp_db_path)

    def test_normal_no_action(self):
        """NORMAL band triggers no response action."""
        assessment = RiskAssessment(
            pid=1234,
            timestamp=time.time(),
            score=10,
            band="NORMAL",
            triggered_rules=[]
        )
        incident = self.engine.act(assessment)
        self.assertIsNone(incident)
        self.assertEqual(len(self.db.get_incidents()), 0)

    def test_throttle_first_three_violations(self):
        """Violations 1 through 3 halve cpu.max quota and log incident."""
        for v in range(1, 4):
            assessment = RiskAssessment(
                pid=1234,
                timestamp=time.time(),
                score=50,
                band="MEDIUM",
                triggered_rules=[RuleResult("SUSPICIOUS_ACTIVITY", 20, "resource spike")]
            )
            incident = self.engine.act(assessment)
            self.assertIsNotNone(incident)
            self.assertEqual(incident.action_taken, "THROTTLE_CPU")
            self.assertEqual(incident.resolution, "THROTTLED")

        # After 3 halvings (40000 -> 20000 -> 10000 -> 5000)
        with open(self.cpu_max_path, "r") as f:
            content = f.read().strip()
        self.assertEqual(content, "5000 100000")

        # Verify 3 incidents saved in DB
        incidents = self.db.get_incidents(pid=1234)
        self.assertEqual(len(incidents), 3)

    def test_sigkill_and_freeze_after_three_violations(self):
        """4th violation (>3) sends SIGKILL, freezes cgroup, and logs."""
        # First 3 violations
        for _ in range(3):
            self.engine.act(RiskAssessment(
                pid=99999, timestamp=time.time(), score=60, band="HIGH",
                triggered_rules=[RuleResult("PERSISTENT_LOAD", 30, "spike")]
            ))

        # 4th violation triggers SIGKILL + FREEZE
        assessment4 = RiskAssessment(
            pid=99999,
            timestamp=time.time(),
            score=95,
            band="CRITICAL",
            triggered_rules=[RuleResult("FORK_BOMB_ACTIVE", 40, "too many procs")]
        )

        with patch("os.kill") as mock_kill:
            incident = self.engine.act(assessment4)
            self.assertIsNotNone(incident)
            self.assertEqual(incident.action_taken, "SIGKILL_FREEZE")
            self.assertEqual(incident.resolution, "TERMINATED")
            mock_kill.assert_called_once_with(99999, SIGKILL)

        # Check cgroup.freeze was written with 1
        with open(self.freeze_path, "r") as f:
            freeze_val = f.read().strip()
        self.assertEqual(freeze_val, "1")

        # Verify persisted in DB
        incidents = self.db.get_incidents(pid=99999)
        self.assertEqual(len(incidents), 4)
        self.assertEqual(incidents[-1]["action_taken"], "SIGKILL_FREEZE")


if __name__ == "__main__":
    unittest.main()
