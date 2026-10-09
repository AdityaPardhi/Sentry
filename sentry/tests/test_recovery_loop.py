"""
test_recovery_loop.py — Unit tests for Phase 9 (Recovery Loop & Escalation)

Tests:
  - Step 9.1: Pre/post-action metric verification (e.g. CPU 85% -> 25%)
  - Step 9.2: State machine: PENDING -> RECOVERED and PENDING -> ESCALATED
  - Step 9.2: Automatic escalation to next tier (Tier 1 -> Tier 2 -> Tier 3)
  - Step 9.3: Resolution persistence in SQLite incidents table
"""

import os
import sys
import time
import signal
import unittest
import tempfile
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.database import SentryDB
from monitor.risk_engine import RiskAssessment, RuleResult
from monitor.response_engine import ResponseEngine, Incident


class TestRecoveryLoop(unittest.TestCase):

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.db = SentryDB(self.temp_db_path)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cgroup_dir = self.temp_dir.name

        self.cpu_max_path = os.path.join(self.cgroup_dir, "cpu.max")
        with open(self.cpu_max_path, "w") as f:
            f.write("40000 100000\n")

        self.engine = ResponseEngine(db=self.db, cgroup_path=self.cgroup_dir)

    def tearDown(self):
        self.temp_dir.cleanup()
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.unlink(self.temp_db_path)

    def test_successful_recovery(self):
        """Step 9.1 & 9.3: Threat drops post-action -> Marked RECOVERED."""
        assessment = RiskAssessment(
            pid=2001,
            timestamp=time.time(),
            score=50,
            band="MEDIUM",
            triggered_rules=[RuleResult("CPU_ANOMALY", 15, "high CPU")]
        )

        # Action taken with pre_metric = 85.0
        inc = self.engine.act(assessment, pre_metric=85.0)
        self.assertIsNotNone(inc)
        self.assertEqual(inc.resolution, "PENDING")

        # Tick 1 (recheck countdown = 1)
        res1 = self.engine.check_recovery(assessment, current_metric_value=75.0)
        self.assertEqual(len(res1), 0)

        # Tick 2 (recheck fires! CPU has dropped to 25.0, band NORMAL)
        normal_assessment = RiskAssessment(pid=2001, timestamp=time.time(), score=10, band="NORMAL", triggered_rules=[])
        res2 = self.engine.check_recovery(normal_assessment, current_metric_value=25.0)
        self.assertEqual(len(res2), 1)
        status, recovered_inc = res2[0]
        self.assertEqual(status, "RECOVERED")
        self.assertEqual(recovered_inc.resolution, "RECOVERED")
        self.assertEqual(recovered_inc.post_metric, 25.0)

        # Verify DB updated
        rows = self.db.get_incidents(pid=2001)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["resolution"], "RECOVERED")
        self.assertEqual(rows[0]["pre_metric"], 85.0)
        self.assertEqual(rows[0]["post_metric"], 25.0)

    def test_escalation_when_threat_persists(self):
        """Step 9.2: Threat remains high -> Marked ESCALATED and triggers next tier."""
        assessment = RiskAssessment(
            pid=2002,
            timestamp=time.time(),
            score=50,
            band="MEDIUM",
            triggered_rules=[RuleResult("CPU_ANOMALY", 15, "high CPU")]
        )

        # Action Tier 1 taken with pre_metric = 90.0
        inc = self.engine.act(assessment, pre_metric=90.0)
        self.assertIsNotNone(inc)
        self.assertEqual(self.engine.current_tier, "TIER1_HALVED")

        # Tick 1
        self.engine.check_recovery(assessment, current_metric_value=88.0)

        # Tick 2 (recheck fires! CPU is STILL 85.0, band still MEDIUM)
        res = self.engine.check_recovery(assessment, current_metric_value=85.0)
        # Should contain ('ESCALATED', inc) and ('TIER_ESCALATED', escalated_inc)
        self.assertGreaterEqual(len(res), 2)
        self.assertEqual(res[0][0], "ESCALATED")
        self.assertEqual(res[1][0], "TIER_ESCALATED")
        self.assertEqual(self.engine.current_tier, "TIER2_AGGRESSIVE")

        # Verify cpu.max was capped to 5000 (Tier 2)
        with open(self.cpu_max_path, "r") as f:
            content = f.read().strip()
        self.assertEqual(content, "5000 100000")

        # Verify incidents table has both the escalated incident and new Tier 2 incident
        rows = self.db.get_incidents(pid=2002)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["resolution"], "ESCALATED")
        self.assertEqual(rows[1]["action_taken"], "THROTTLE_CPU_TIER2_AGGRESSIVE")


if __name__ == "__main__":
    unittest.main()
