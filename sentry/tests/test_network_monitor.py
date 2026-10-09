"""
test_network_monitor.py — Unit tests for Phase 6 (Network Behavior Monitoring)

Tests:
  - Step 6.1: Hex conversion for IPv4 & IPv6, socket state parsing, /proc/net/tcp line decoding
  - Step 6.2: Rolling connection attempt rate calculation (attempts/min)
  - Database persistence in network_samples
  - Real socket detection
"""

import os
import sys
import time
import socket
import unittest
import tempfile
from unittest.mock import patch, mock_open

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.database import SentryDB
from monitor.network_monitor import NetworkMonitor, hex_to_ipv4, hex_to_ipv6, TCP_STATES, SocketInfo


class TestNetworkMonitor(unittest.TestCase):

    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        self.db = SentryDB(self.temp_db_path)

    def tearDown(self):
        os.close(self.temp_db_fd)
        if os.path.exists(self.temp_db_path):
            os.unlink(self.temp_db_path)

    def test_hex_conversion(self):
        """Step 6.1: Verify hex address and port parsing."""
        # 0100007F: 127.0.0.1
        self.assertEqual(hex_to_ipv4("0100007F"), "127.0.0.1")
        # 00000000: 0.0.0.0
        self.assertEqual(hex_to_ipv4("00000000"), "0.0.0.0")
        # 08080808: 8.8.8.8
        self.assertEqual(hex_to_ipv4("08080808"), "8.8.8.8")

        # Port parsing (hex in big-endian)
        self.assertEqual(int("0050", 16), 80)
        self.assertEqual(int("1F90", 16), 8080)

    def test_parse_proc_net_tcp_mock(self):
        """Step 6.1: Parse synthetic /proc/net/tcp output."""
        mock_proc_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 10001 1 ...\n"
            "   1: 0100007F:C001 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 10002 1 ...\n"
            "   2: 0100007F:C002 08080808:0050 02 00000000:00000000 00:00000000 00000000     0        0 10003 1 ...\n"
        )

        with patch("builtins.open", mock_open(read_data=mock_proc_content)):
            with patch("os.path.exists", return_value=True):
                mon = NetworkMonitor(pid=1234, db=self.db)
                sockets = mon.parse_proc_net("tcp")

                self.assertEqual(len(sockets), 3)

                # Socket 0: LISTEN 127.0.0.1:8080
                self.assertEqual(sockets[0].local_ip, "127.0.0.1")
                self.assertEqual(sockets[0].local_port, 8080)
                self.assertEqual(sockets[0].state_name, "LISTEN")

                # Socket 1: ESTABLISHED 127.0.0.1:49153 -> 127.0.0.1:8080
                self.assertEqual(sockets[1].local_port, 49153)
                self.assertEqual(sockets[1].remote_ip, "127.0.0.1")
                self.assertEqual(sockets[1].remote_port, 8080)
                self.assertEqual(sockets[1].state_name, "ESTABLISHED")

                # Socket 2: SYN_SENT -> 8.8.8.8:80
                self.assertEqual(sockets[2].remote_ip, "8.8.8.8")
                self.assertEqual(sockets[2].remote_port, 80)
                self.assertEqual(sockets[2].state_name, "SYN_SENT")

    def test_sample_and_rate_calculation(self):
        """Step 6.2: Verify rolling window rate and sample aggregation."""
        mon = NetworkMonitor(pid=9999, db=self.db)

        # Manually register 10 connection attempts in sliding window
        now = time.time()
        for _ in range(10):
            mon.attempt_timestamps.append(now)

        rate = mon.get_rate()
        self.assertGreater(rate, 0.0)

    def test_db_persistence(self):
        """Step 6.2: Verify network samples are persisted to SQLite."""
        mon = NetworkMonitor(pid=1001, db=self.db)
        s = mon.sample()

        rows = self.db.get_network_samples(pid=1001)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["pid"], 1001)
        self.assertIn("active_connections", rows[0])
        self.assertIn("connection_rate", rows[0])

    def test_live_socket_detection(self):
        """Step 6.1: Open a live TCP socket and ensure NetworkMonitor detects it."""
        # Create a loopback listener socket
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv_port = srv.getsockname()[1]

        # Connect a client socket
        cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cli.connect(("127.0.0.1", srv_port))

        try:
            mon = NetworkMonitor(db=self.db)
            sockets = mon.get_all_sockets()
            ports = [s.local_port for s in sockets] + [s.remote_port for s in sockets]
            self.assertIn(srv_port, ports)
        finally:
            cli.close()
            srv.close()


if __name__ == "__main__":
    unittest.main()
