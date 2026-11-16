# The demo runs the server as root; a real deployment should run it
# unprivileged with a sudoers rule limited to cli/scan.py.

import argparse
import collections
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cli.explain import explain_result

if hasattr(os, "geteuid"):
    if os.geteuid() != 0 and os.environ.get("SENTRY_SCAN_STUB") != "1":
        print("run with sudo")
        sys.exit(1)

DEMO_FILES = {
    "hello": ("demo/hello.sh", "hello.sh"),
    "dropper": ("demo/fake_dropper.sh", "fake_dropper.sh"),
    "noisy": ("demo/noisy.sh", "noisy.sh"),
    "t1_clean": ("bin/t1_clean", "t1_clean"),
    "t2_file_drop": ("bin/t2_file_drop", "t2_file_drop"),
    "t3_secret_reader": ("bin/t3_secret_reader", "t3_secret_reader"),
    "t4_network": ("bin/t4_network", "t4_network"),
    "t5_spawner": ("bin/t5_spawner", "t5_spawner"),
}

CANNED_RESULTS = {
    "hello": {
        "file_name": "hello.sh",
        "sha256": "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
        "file_type": "POSIX shell script, ASCII text executable",
        "verdict": "NO ISSUES OBSERVED",
        "score": 3,
        "static_score": 0,
        "dynamic_score": 3,
        "dynamic_ran": True,
        "duration_seconds": 1.1,
        "findings": [],
        "timeline": [
            {"t": 0.0, "cpu_percent": 1.2, "rss_mb": 4.0, "processes": 1},
            {"t": 0.2, "cpu_percent": 2.0, "rss_mb": 4.1, "processes": 1},
            {"t": 0.4, "cpu_percent": 1.5, "rss_mb": 4.1, "processes": 1},
            {"t": 0.6, "cpu_percent": 2.1, "rss_mb": 4.2, "processes": 1},
            {"t": 0.8, "cpu_percent": 1.0, "rss_mb": 4.0, "processes": 1},
            {"t": 1.0, "cpu_percent": 0.8, "rss_mb": 4.0, "processes": 1},
        ],
        "notes": ["Target exited normally with code 0", "No suspicious activity detected"],
        "sandbox_log": "[sentry] Initializing sandbox isolation...\n[sentry] Running hello.sh...\n[sentry] Execution finished with exit code 0.\n",
        "error": None,
    },
    "dropper": {
        "file_name": "fake_dropper.sh",
        "sha256": "7d1a54127b222502f5b79b5fb0803061152a44f92b37e23c65c53d9e1b7c2514",
        "file_type": "POSIX shell script, ASCII text executable",
        "verdict": "MALICIOUS",
        "score": 85,
        "static_score": 75,
        "dynamic_score": 10,
        "dynamic_ran": True,
        "duration_seconds": 2.3,
        "findings": [
            {"source": "static", "rule": "shell_pipe_download", "points": 25, "reason": "pipes a download straight into a shell"},
            {"source": "static", "rule": "ssh_key_touch", "points": 25, "reason": "touches SSH keys"},
            {"source": "static", "rule": "persistence_cron", "points": 25, "reason": "tries to persist across reboots"},
            {"source": "dynamic", "rule": "network_blocked", "points": 10, "reason": "network connection blocked by seccomp"},
        ],
        "timeline": [
            {"t": 0.0, "cpu_percent": 2.0, "rss_mb": 5.2, "processes": 1},
            {"t": 0.2, "cpu_percent": 15.0, "rss_mb": 6.8, "processes": 2},
            {"t": 0.4, "cpu_percent": 48.0, "rss_mb": 8.1, "processes": 4},
            {"t": 0.6, "cpu_percent": 52.0, "rss_mb": 8.5, "processes": 3},
            {"t": 0.8, "cpu_percent": 12.0, "rss_mb": 8.5, "processes": 1},
            {"t": 1.0, "cpu_percent": 0.0, "rss_mb": 0.0, "processes": 0},
        ],
        "notes": ["Attempted connection to remote IP address", "Attempted persistence installation via crontab"],
        "sandbox_log": "[sentry] Initializing sandbox isolation...\n[sentry] Syscall connect() blocked by seccomp policy.\n[sentry] Child process terminated.\n",
        "error": None,
    },
    "noisy": {
        "file_name": "noisy.sh",
        "sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
        "file_type": "POSIX shell script, ASCII text executable",
        "verdict": "SUSPICIOUS",
        "score": 46,
        "static_score": 0,
        "dynamic_score": 46,
        "dynamic_ran": True,
        "duration_seconds": 3.2,
        "findings": [
            {"source": "dynamic", "rule": "process_burst", "points": 25, "reason": "process count burst (31 processes)"},
            {"source": "dynamic", "rule": "mass_file_writes", "points": 15, "reason": "high file write rate (210 files/min)"},
            {"source": "dynamic", "rule": "cpu_spike", "points": 6, "reason": "CPU spike exceeding threshold"},
        ],
        "timeline": [
            {"t": 0.0, "cpu_percent": 4.0, "rss_mb": 6.0, "processes": 1},
            {"t": 0.3, "cpu_percent": 18.0, "rss_mb": 12.0, "processes": 3},
            {"t": 0.6, "cpu_percent": 45.0, "rss_mb": 24.0, "processes": 10},
            {"t": 0.9, "cpu_percent": 72.0, "rss_mb": 42.0, "processes": 20},
            {"t": 1.2, "cpu_percent": 91.0, "rss_mb": 58.0, "processes": 28},
            {"t": 1.5, "cpu_percent": 96.0, "rss_mb": 64.0, "processes": 31},
            {"t": 1.8, "cpu_percent": 84.0, "rss_mb": 64.0, "processes": 31},
            {"t": 2.1, "cpu_percent": 60.0, "rss_mb": 63.5, "processes": 30},
            {"t": 2.4, "cpu_percent": 49.4, "rss_mb": 63.0, "processes": 30},
            {"t": 2.7, "cpu_percent": 48.8, "rss_mb": 63.0, "processes": 30},
        ],
        "notes": ["Process limit hit in cgroup pids.max", "High file write rate detected"],
        "sandbox_log": "[sentry] Initializing sandbox isolation...\n[sentry] Monitor: high file write rate (210 files/min)\n[sentry] Process count hit cgroup limit.\n",
        "error": None,
    },
}


def sanitize_display_name(raw_name):
    clean = re.sub(r"[^a-zA-Z0-9._-]", "_", raw_name)[:80]
    return clean if clean else "untrusted"


def detect_file_type_from_bytes(raw_bytes, filename):
    """Return a human-readable file type string from magic bytes and extension."""
    head = raw_bytes[:256] if len(raw_bytes) >= 256 else raw_bytes
    if head[:4] == b"\x7fELF":
        return "ELF executable"
    if head[:2] == b"MZ":
        return "Windows PE executable"
    if head[:2] == b"#!":
        shebang_line = head.split(b"\n", 1)[0][2:].decode(errors="ignore").strip()
        parts = shebang_line.split()
        if parts:
            interp = os.path.basename(parts[0])
            if interp == "env" and len(parts) > 1:
                interp = os.path.basename(parts[1])
            return f"POSIX shell script ({interp})" if interp in ("sh", "bash", "dash") else f"Script ({interp})"
    # Fall back to extension
    lower = (filename or "").lower()
    if lower.endswith((".c", ".cc", ".cpp", ".cxx")):
        return "C source"
    if lower.endswith(".h"):
        return "C header"
    if lower.endswith(".py"):
        return "Python script"
    if lower.endswith((".sh", ".bash")):
        return "POSIX shell script"
    if lower.endswith(".rs"):
        return "Rust source"
    if lower.endswith(".go"):
        return "Go source"
    if lower.endswith(".java"):
        return "Java source"
    return "Binary/unknown"


def get_stub_result(scenario, display_name):
    # Map t1-t5 to plausible canned scenarios
    _alias = {
        "t1_clean": "hello",
        "t2_file_drop": "noisy",
        "t3_secret_reader": "noisy",
        "t4_network": "dropper",
        "t5_spawner": "noisy",
    }
    base = _alias.get(scenario, scenario)
    template = CANNED_RESULTS.get(base, CANNED_RESULTS["hello"])
    res = dict(template)
    res["findings"] = [dict(f) for f in template["findings"]]
    res["timeline"] = [dict(pt) for pt in template["timeline"]]
    res["notes"] = list(template["notes"])
    res["file_name"] = display_name
    res["size_bytes"] = 1024
    res["thresholds"] = {"suspicious": 21, "malicious": 61}
    if base == "dropper":
        res["killed_by_signal"] = "SIGSYS"
        res["exit_code"] = None
    else:
        res["exit_code"] = 0
        res["killed_by_signal"] = None
    res["behavior"] = {
        "verdict": res.get("verdict", "SAFE"),
        "score": res.get("dynamic_score", 0),
        "coverage": {
            "files_written": "observed",
            "network": "not_monitored",
            "file_reads": "not_monitored",
            "processes": "sampled",
        },
        "files_written": {"count": 2 if base == "noisy" else 0, "examples": ["/tmp/out.txt"] if base == "noisy" else []},
        "network_attempts": {"count": 1 if base == "dropper" else 0, "examples": ["198.51.100.1:4444"] if base == "dropper" else []},
        "processes_spawned": {"count": 31 if base == "noisy" else 1, "examples": ["31 concurrent children"] if base == "noisy" else []},
    }
    res["reasons"] = [
        {
            "category": f.get("source", "process") if f.get("source") == "static" else ("seccomp" if "seccomp" in f.get("rule","") or "network" in f.get("rule","") else ("file" if "file" in f.get("rule","") else "process")),
            "points": f.get("points", 0),
            "reason": f.get("reason", ""),
        }
        for f in res.get("findings", [])
    ]
    return res


class SentryHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Keep output clean; do not spam logs
        pass

    def send_json(self, status_code, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status_code, message):
        self.send_json(status_code, {"error": message})

    def validate_host(self):
        allowed_hosts = {
            f"127.0.0.1:{self.server.server_port}",
            f"localhost:{self.server.server_port}",
        }
        host = self.headers.get("Host", "").strip()
        if host not in allowed_hosts:
            self.send_error_json(403, "Forbidden: Invalid Host header")
            return False
        return True

    def validate_token(self):
        token = self.headers.get("X-Sentry-Token", "")
        if not secrets.compare_digest(token, self.server.token):
            self.send_error_json(403, "Forbidden: Invalid or missing X-Sentry-Token")
            return False
        return True

    def do_GET(self):
        if not self.validate_host():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if path.startswith("/api/"):
            if not self.validate_token():
                return

            if path == "/api/health":
                self.send_json(200, {"ok": True, "live": True})
                return

            if path == "/api/history":
                with self.server.history_lock:
                    items = list(self.server.history)
                self.send_json(200, items)
                return

            self.send_error_json(404, "Not Found")
            return

        if path in ("/", "/index.html"):
            demo_file = os.path.join("web", "demo.html")
            try:
                with open(demo_file, "r", encoding="utf-8") as f:
                    content = f.read()
                content = content.replace("__SENTRY_TOKEN__", self.server.token)
                body = content.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except Exception as e:
                self.send_error_json(500, f"Error reading web/demo.html: {e}")
            return

        self.send_error_json(404, "Not Found")

    def do_POST(self):
        if not self.validate_host():
            return

        parsed = urlparse(self.path)
        path = parsed.path

        if not path.startswith("/api/"):
            self.send_error_json(404, "Not Found")
            return

        if not self.validate_token():
            return

        query_params = parse_qs(parsed.query)

        if path.startswith("/api/demo/"):
            scenario = path[len("/api/demo/"):]
            if scenario not in DEMO_FILES:
                self.send_error_json(404, "Not Found")
                return
            self.handle_demo_scan(scenario, query_params)
            return

        if path == "/api/scan":
            self.handle_file_scan(query_params)
            return

        self.send_error_json(404, "Not Found")

    def parse_timeout(self, query_params):
        timeout_str = query_params.get("timeout", ["10"])[0]
        try:
            t = int(timeout_str)
        except ValueError:
            t = 10
        return max(1, min(60, t))

    def handle_demo_scan(self, scenario, query_params):
        if not self.server.scan_lock.acquire(blocking=False):
            self.send_error_json(429, "A scan is already in progress")
            return

        try:
            timeout_val = self.parse_timeout(query_params)
            demo_path, default_name = DEMO_FILES[scenario]
            sanitized_name = sanitize_display_name(query_params.get("name", [default_name])[0])

            if os.environ.get("SENTRY_SCAN_STUB") == "1":
                delay_str = os.environ.get("SENTRY_SCAN_DELAY", "1")
                try:
                    delay = float(delay_str)
                except ValueError:
                    delay = 1.0
                if delay > 0:
                    time.sleep(delay)
                result = get_stub_result(scenario, sanitized_name)
            else:
                cmd = [
                    sys.executable,
                    "cli/scan.py",
                    demo_path,
                    "--json",
                    "--timeout",
                    str(timeout_val),
                ]
                try:
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout_val + 40,
                    )
                    result = json.loads(proc.stdout)
                    if not isinstance(result, dict):
                        raise ValueError("Scanner output is not a JSON object")
                except subprocess.TimeoutExpired:
                    self.send_error_json(500, "Scanner timed out")
                    return
                except Exception as e:
                    self.send_error_json(500, f"Scanner output error: {e}")
                    return

            result["file_name"] = sanitized_name
            result["ai_explanation"] = explain_result(result)
            with self.server.history_lock:
                self.server.history.appendleft(result)
            self.send_json(200, result)
        finally:
            self.server.scan_lock.release()

    def handle_file_scan(self, query_params):
        max_bytes = 20 * 1024 * 1024
        content_length_header = self.headers.get("Content-Length")
        if not content_length_header:
            self.send_error_json(400, "no file provided")
            return

        try:
            content_length = int(content_length_header)
        except ValueError:
            self.send_error_json(400, "Invalid Content-Length")
            return

        if content_length == 0:
            self.send_error_json(400, "no file provided")
            return

        if content_length > max_bytes:
            self.send_error_json(413, "Payload Too Large: maximum 20 MB")
            return

        raw_bytes = self.rfile.read(content_length)
        if len(raw_bytes) == 0:
            self.send_error_json(400, "no file provided")
            return
        if len(raw_bytes) > max_bytes:
            self.send_error_json(413, "Payload Too Large: maximum 20 MB")
            return

        if not self.server.scan_lock.acquire(blocking=False):
            self.send_error_json(429, "A scan is already in progress")
            return

        temp_dir = None
        temp_file_path = None
        try:
            timeout_val = self.parse_timeout(query_params)
            raw_name = query_params.get("name", ["untrusted"])[0]
            sanitized_name = sanitize_display_name(raw_name)

            _, ext = os.path.splitext(sanitized_name)
            ext = ext.lower()
            if not re.match(r"^\.[a-z0-9]{1,5}$", ext):
                ext = ""

            temp_dir = tempfile.mkdtemp(prefix="sentry_scan_")
            try:
                os.chmod(temp_dir, 0o700)
            except OSError:
                pass

            rand_filename = f"scan_{secrets.token_hex(12)}{ext}"
            temp_file_path = os.path.join(temp_dir, rand_filename)
            with open(temp_file_path, "wb") as f:
                f.write(raw_bytes)

            compile_requested = query_params.get("compile", ["0"])[0] in ("1", "true")
            scan_target = temp_file_path
            is_compiled = False

            if compile_requested and ext in (".c", ".cpp", ".cc"):
                compiled_bin = os.path.join(temp_dir, "myprog")
                compiler = "g++" if ext in (".cpp", ".cc") else "gcc"
                compile_cmd = [compiler, "-static", "-O2", "-o", compiled_bin, temp_file_path]
                res = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=30)
                if res.returncode != 0:
                    compile_cmd = [compiler, "-O2", "-o", compiled_bin, temp_file_path]
                    res = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=30)
                if res.returncode != 0:
                    err_txt = res.stderr.strip() or res.stdout.strip() or "gcc compilation failed"
                    self.send_error_json(400, f"Compilation failed: {err_txt[:300]}")
                    return
                scan_target = compiled_bin
                is_compiled = True

            if os.environ.get("SENTRY_SCAN_STUB") == "1":
                delay_str = os.environ.get("SENTRY_SCAN_DELAY", "1")
                try:
                    delay = float(delay_str)
                except ValueError:
                    delay = 1.0
                if delay > 0:
                    time.sleep(delay)

                lower_name = sanitized_name.lower()
                if "dropper" in lower_name:
                    scenario = "dropper"
                elif "noisy" in lower_name:
                    scenario = "noisy"
                elif "t1_clean" in lower_name:
                    scenario = "t1_clean"
                elif "t2_file_drop" in lower_name:
                    scenario = "t2_file_drop"
                elif "t3_secret_reader" in lower_name:
                    scenario = "t3_secret_reader"
                elif "t4_network" in lower_name:
                    scenario = "t4_network"
                elif "t5_spawner" in lower_name:
                    scenario = "t5_spawner"
                else:
                    scenario = "hello"
                result = get_stub_result(scenario, sanitized_name)
                # Overwrite stub metadata with real values from the uploaded bytes
                if is_compiled and os.path.exists(scan_target):
                    with open(scan_target, "rb") as bf:
                        bin_bytes = bf.read()
                    result["sha256"] = hashlib.sha256(bin_bytes).hexdigest()
                    result["size_bytes"] = len(bin_bytes)
                    result["file_type"] = detect_file_type_from_bytes(bin_bytes, "myprog")
                else:
                    result["sha256"] = hashlib.sha256(raw_bytes).hexdigest()
                    result["size_bytes"] = len(raw_bytes)
                    result["file_type"] = detect_file_type_from_bytes(raw_bytes, sanitized_name)
            else:
                cmd = [
                    sys.executable,
                    "cli/scan.py",
                    scan_target,
                    "--json",
                    "--timeout",
                    str(timeout_val),
                ]
                try:
                    proc = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout_val + 40,
                    )
                    result = json.loads(proc.stdout)
                    if not isinstance(result, dict):
                        raise ValueError("Scanner output is not a JSON object")
                except subprocess.TimeoutExpired:
                    self.send_error_json(500, "Scanner timed out")
                    return
                except Exception as e:
                    self.send_error_json(500, f"Scanner output error: {e}")
                    return

            if is_compiled:
                result["compiled"] = True
                result["file_name"] = f"{sanitized_name} (compiled)"
            else:
                result["file_name"] = sanitized_name
            result["ai_explanation"] = explain_result(result)
            with self.server.history_lock:
                self.server.history.appendleft(result)
            self.send_json(200, result)
        finally:
            if temp_file_path and os.path.exists(temp_file_path):
                try:
                    os.remove(temp_file_path)
                except OSError:
                    pass
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            self.server.scan_lock.release()


def main():
    parser = argparse.ArgumentParser(description="SENTRY Sandbox Web Server")
    parser.add_argument("--port", type=int, default=8080, help="Port to bind (default 8080)")
    args = parser.parse_args()

    token = secrets.token_urlsafe(16)
    server_address = ("127.0.0.1", args.port)
    httpd = ThreadingHTTPServer(server_address, SentryHandler)
    httpd.server_port = args.port
    httpd.token = token
    httpd.scan_lock = threading.Lock()
    httpd.history_lock = threading.Lock()
    httpd.history = collections.deque(maxlen=20)

    print(f"http://127.0.0.1:{args.port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()

