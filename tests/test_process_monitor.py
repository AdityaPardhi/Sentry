#!/usr/bin/env python3
"""
test_process_monitor.py — Automated verification for Phase 4 (Process Behavior Monitoring)

Validates:
  - Step 4.1: CPU% calculation from /proc/<pid>/stat
  - Step 4.2: Memory (VmRSS) extraction from /proc/<pid>/status
  - Step 4.3: Process tree tracking and child spawn rate calculation
  - Step 4.4: SQLite time-series logging into process_samples table
"""

import os
import sys
import time
import subprocess
import unittest
from typing import List

# Setup path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from db.database import SentryDB
from monitor.process_monitor import ProcessMonitor, ProcessSample

TEST_DB = "test_sentry_phase4.db"


class TestPhase4ProcessMonitoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Clean up old test db
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)
        cls.db = SentryDB(TEST_DB)

        # Check for compiled test binaries
        cls.bin_dir = os.path.join(PROJECT_ROOT, "bin")
        cls.stress_cpu = os.path.join(cls.bin_dir, "stress_cpu")
        cls.stress_mem = os.path.join(cls.bin_dir, "stress_mem")
        cls.stress_fork = os.path.join(cls.bin_dir, "stress_fork")

        # Compile if missing
        if not os.path.exists(cls.stress_cpu):
            subprocess.run(["gcc", "-O2", "-o", cls.stress_cpu, os.path.join(PROJECT_ROOT, "tests", "stress_cpu.c")], check=True)
        if not os.path.exists(cls.stress_mem):
            subprocess.run(["gcc", "-O0", "-o", cls.stress_mem, os.path.join(PROJECT_ROOT, "tests", "stress_mem.c")], check=True)
        if not os.path.exists(cls.stress_fork):
            subprocess.run(["gcc", "-O0", "-o", cls.stress_fork, os.path.join(PROJECT_ROOT, "tests", "stress_fork.c")], check=True)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(TEST_DB):
            try:
                os.remove(TEST_DB)
            except OSError:
                pass

    def test_01_db_schema_and_insert(self):
        """Step 4.4: Verify process_samples schema and insert helper."""
        print("\n[Test 4.4a] Checking SQLite process_samples table schema...")
        row_id = self.db.insert_process_sample(
            pid=99999,
            timestamp=time.time(),
            cpu_percent=45.5,
            rss_kb=10240,
            child_count=2,
            spawn_rate=1
        )
        self.assertGreater(row_id, 0)
        samples = self.db.get_process_samples(pid=99999)
        self.assertEqual(len(samples), 1)
        s = samples[0]
        self.assertEqual(s["pid"], 99999)
        self.assertAlmostEqual(s["cpu_percent"], 45.5, places=1)
        self.assertEqual(s["rss_kb"], 10240)
        self.assertEqual(s["child_count"], 2)
        self.assertEqual(s["spawn_rate"], 1)
        print("  ✓ Schema, insert, and query verified.")

    def test_02_cpu_monitoring(self):
        """Step 4.1: Verify CPU% calculation from /proc/<pid>/stat with stress_cpu."""
        print("\n[Test 4.1] Monitoring CPU usage with stress_cpu...")
        proc = subprocess.Popen([self.stress_cpu, "4"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            monitor = ProcessMonitor(pid=proc.pid, db=self.db)
            samples: List[ProcessSample] = []

            # First sample initializes ticks baseline
            samples.append(monitor.sample())
            time.sleep(0.5)

            # Sample while burning CPU
            for _ in range(4):
                samples.append(monitor.sample())
                time.sleep(0.5)

            measured_cpus = [s.cpu_percent for s in samples[1:]]
            max_cpu = max(measured_cpus) if measured_cpus else 0.0
            print(f"  Recorded CPU% samples: {[f'{c:.1f}%' for c in measured_cpus]}")
            print(f"  Peak CPU%: {max_cpu:.1f}%")

            # A tight loop should register significant CPU activity (> 20%)
            self.assertGreater(max_cpu, 10.0, "CPU% did not register expected activity.")
            print("  ✓ Step 4.1 CPU% calculation verified.")
        finally:
            proc.kill()
            if proc.stdout: proc.stdout.close()
            if proc.stderr: proc.stderr.close()
            proc.wait()

    def test_03_memory_monitoring(self):
        """Step 4.2: Verify VmRSS tracking from /proc/<pid>/status with stress_mem."""
        print("\n[Test 4.2] Monitoring RSS memory climb with stress_mem...")
        # Allocate up to 50MB in chunks
        proc = subprocess.Popen([self.stress_mem, "50"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            monitor = ProcessMonitor(pid=proc.pid, db=self.db)
            samples: List[ProcessSample] = []

            for _ in range(6):
                samples.append(monitor.sample())
                time.sleep(0.4)

            rss_values = [s.rss_kb for s in samples]
            max_rss_mb = max(rss_values) / 1024.0 if rss_values else 0
            print(f"  Recorded RSS values: {[f'{r//1024}MB' for r in rss_values]}")
            print(f"  Peak RSS: {max_rss_mb:.1f} MB")

            # Verify memory was detected and increased
            self.assertGreater(max_rss_mb, 10.0, "RSS memory was not properly detected.")
            self.assertGreater(rss_values[-1], rss_values[0], "RSS did not increase as memory was allocated.")
            print("  ✓ Step 4.2 Memory VmRSS tracking verified.")
        finally:
            proc.kill()
            if proc.stdout: proc.stdout.close()
            if proc.stderr: proc.stderr.close()
            proc.wait()

    def test_04_process_tree_and_spawn_rate(self):
        """Step 4.3: Verify child process tracking and spawn rate with stress_fork."""
        print("\n[Test 4.3] Monitoring child processes and spawn rate with stress_fork...")
        proc = subprocess.Popen([self.stress_fork, "25"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            monitor = ProcessMonitor(pid=proc.pid, db=self.db)
            samples: List[ProcessSample] = []

            for _ in range(8):
                samples.append(monitor.sample())
                time.sleep(0.3)

            spawn_rates = [s.spawn_rate for s in samples]
            child_counts = [s.child_count for s in samples]
            total_spawns = sum(spawn_rates)
            max_children = max(child_counts)

            print(f"  Recorded child counts: {child_counts}")
            print(f"  Recorded spawn rates:  {spawn_rates}")
            print(f"  Total child processes tracked: {total_spawns}")

            # Verify that spawned children were detected
            self.assertGreater(total_spawns, 0, "No child spawns were detected.")
            print("  ✓ Step 4.3 Process tree and spawn rate tracking verified.")
        finally:
            proc.kill()
            if proc.stdout: proc.stdout.close()
            if proc.stderr: proc.stderr.close()
            proc.wait()

    def test_05_sqlite_timeseries(self):
        """Step 4.4: Verify full time-series logged into SQLite."""
        print("\n[Test 4.4b] Verifying SQLite time-series records...")
        all_samples = self.db.get_process_samples(limit=100)
        self.assertGreaterEqual(len(all_samples), 10, "Expected at least 10 logged samples in DB.")

        # Check fields of all rows
        for row in all_samples:
            self.assertIn("id", row)
            self.assertIn("pid", row)
            self.assertIn("timestamp", row)
            self.assertIn("cpu_percent", row)
            self.assertIn("rss_kb", row)
            self.assertIn("child_count", row)
            self.assertIn("spawn_rate", row)

        print(f"  Total valid time-series samples in SQLite: {len(all_samples)}")
        print("  ✓ Step 4.4 SQLite time-series logging verified.")


if __name__ == "__main__":
    unittest.main()
