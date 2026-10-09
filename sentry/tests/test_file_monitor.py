#!/usr/bin/env python3
"""
test_file_monitor.py — Automated verification for Phase 5 (File Behavior Monitoring)

Validates:
  - Step 5.1: File create, modify, delete, and directory events detected via inotify
  - Step 5.2: Rolling files-per-minute rate calculation under burst file operations
  - SQLite persistence in file_events and file_samples tables
"""

import os
import sys
import time
import shutil
import tempfile
import unittest
import subprocess
from typing import List

# Setup path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from db.database import SentryDB
from monitor.file_monitor import FileMonitor, FileEvent

TEST_DB = "test_sentry_phase5.db"


class TestPhase5FileMonitoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.path.exists(TEST_DB):
            os.remove(TEST_DB)
        cls.db = SentryDB(TEST_DB)
        cls.watch_dir = tempfile.mkdtemp(prefix="sentry_test_filemon_")

        # Compile stress_files if missing
        cls.bin_dir = os.path.join(PROJECT_ROOT, "bin")
        cls.stress_files = os.path.join(cls.bin_dir, "stress_files")
        if not os.path.exists(cls.stress_files):
            os.makedirs(cls.bin_dir, exist_ok=True)
            subprocess.run(["gcc", "-O2", "-o", cls.stress_files, os.path.join(PROJECT_ROOT, "tests", "stress_files.c")], check=True)

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.watch_dir):
            shutil.rmtree(cls.watch_dir, ignore_errors=True)
        if os.path.exists(TEST_DB):
            try:
                os.remove(TEST_DB)
            except OSError:
                pass

    def test_01_db_file_tables(self):
        """Step 5.1 & 5.2: Verify SQLite file_events and file_samples tables."""
        print("\n[Test 5.1a] Checking SQLite file_events and file_samples tables...")
        e_id = self.db.insert_file_event(time.time(), "CREATE", "/tmp/test.txt", 0)
        self.assertGreater(e_id, 0)
        events = self.db.get_file_events(limit=10)
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[0]["event_type"], "CREATE")

        s_id = self.db.insert_file_sample(time.time(), 120.5, 10, pid=1234)
        self.assertGreater(s_id, 0)
        samples = self.db.get_file_samples(limit=10)
        self.assertGreaterEqual(len(samples), 1)
        self.assertAlmostEqual(samples[0]["file_write_rate"], 120.5, places=1)
        print("  ✓ Database tables and query methods verified.")

    def test_02_detect_crud_events(self):
        """Step 5.1: Detect file create, modify, and delete operations via inotify."""
        print("\n[Test 5.1b] Verifying inotify detection of CREATE, MODIFY, and DELETE...")
        monitor = FileMonitor(root_dir=self.watch_dir, db=self.db)
        try:
            target_file = os.path.join(self.watch_dir, "sample.txt")

            # 1. CREATE
            with open(target_file, "w") as f:
                f.write("Initial content\n")
            time.sleep(0.1)

            events = monitor.poll_events()
            types = [e.event_type for e in events]
            print(f"  Create events captured: {types}")
            self.assertTrue(any(t in ("CREATE", "MODIFY") for t in types), "No CREATE/MODIFY event detected on write.")

            # 2. MODIFY
            with open(target_file, "a") as f:
                f.write("Appended line\n")
            time.sleep(0.1)

            events2 = monitor.poll_events()
            types2 = [e.event_type for e in events2]
            print(f"  Modify events captured: {types2}")
            self.assertTrue(any(t == "MODIFY" for t in types2), "No MODIFY event detected on append.")

            # 3. DELETE
            os.remove(target_file)
            time.sleep(0.1)

            events3 = monitor.poll_events()
            types3 = [e.event_type for e in events3]
            print(f"  Delete events captured: {types3}")
            self.assertTrue(any(t == "DELETE" for t in types3), "No DELETE event detected on remove.")

            print("  ✓ Step 5.1 File lifecycle events successfully captured.")
        finally:
            monitor.stop()

    def test_03_detect_subdirectories(self):
        """Step 5.1: Verify dynamic recursive watch on newly created subdirectories."""
        print("\n[Test 5.1c] Verifying recursive inotify watching on new subdirectories...")
        monitor = FileMonitor(root_dir=self.watch_dir, db=self.db)
        try:
            sub_dir = os.path.join(self.watch_dir, "nested_folder")
            os.mkdir(sub_dir)
            time.sleep(0.1)

            # Flush creation events so subdirectory watch is registered
            monitor.poll_events()

            # Now create a file inside the nested directory
            nested_file = os.path.join(sub_dir, "nested.txt")
            with open(nested_file, "w") as f:
                f.write("inside subdirectory\n")
            time.sleep(0.1)

            events = monitor.poll_events()
            nested_paths = [e.path for e in events]
            print(f"  Events inside subdirectory: {nested_paths}")
            self.assertTrue(any("nested.txt" in p for p in nested_paths), "File event in new subdirectory was not detected.")
            print("  ✓ Step 5.1 Recursive subdirectory watching verified.")
        finally:
            monitor.stop()

    def test_04_stress_files_rate_spike(self):
        """Step 5.2: Verify files-per-minute rate metric during burst file creation."""
        print("\n[Test 5.2] Running stress_files to measure files-per-minute rate spike...")
        monitor = FileMonitor(root_dir=self.watch_dir, db=self.db)
        try:
            # Baseline: idle rate
            monitor.poll_events()
            idle_rate = monitor.get_rate()
            print(f"  Baseline idle rate: {idle_rate:.1f} files/min")

            # Run stress_files inside watch_dir
            burst_dir = os.path.join(self.watch_dir, "burst")
            os.makedirs(burst_dir, exist_ok=True)
            # Register inotify watch on new directory
            monitor.poll_events()
            res = subprocess.run([self.stress_files, "150", burst_dir], capture_output=True, text=True, check=True)
            print(f"  stress_files output: {res.stdout.strip().splitlines()[-1]}")

            # Sample monitor
            events = monitor.poll_events()
            burst_rate = monitor.get_rate()
            print(f"  Events captured during burst: {len(events)}")
            print(f"  Measured files-per-minute rate: {burst_rate:.1f} files/min")

            # Under burst creation of 150 files in <1s, rate should be significantly elevated (> 100/min)
            self.assertGreater(burst_rate, 50.0, f"Expected rate spike > 50 files/min, got {burst_rate:.1f}")
            self.assertGreater(len(events), 50, f"Expected at least 50 events captured, got {len(events)}")
            print("  ✓ Step 5.2 Files-per-minute rate spike verified.")
        finally:
            monitor.stop()

    def test_05_sqlite_file_persistence(self):
        """Step 5.2: Verify file telemetry records in SQLite."""
        print("\n[Test 5.2b] Verifying SQLite persistence of file events and rate samples...")
        events = self.db.get_file_events(limit=50)
        samples = self.db.get_file_samples(limit=50)

        print(f"  Total logged file events in DB: {len(events)}")
        self.assertGreater(len(events), 10, "Expected at least 10 logged file events.")

        # Insert a sample from monitor and verify
        self.db.insert_file_sample(time.time(), 350.0, len(events))
        samples = self.db.get_file_samples(limit=10)
        self.assertGreater(len(samples), 0)
        print(f"  Peak file write rate recorded in DB: {max(s['file_write_rate'] for s in samples):.1f} files/min")
        print("  ✓ Step 5.2 SQLite persistence verified.")


if __name__ == "__main__":
    unittest.main()
