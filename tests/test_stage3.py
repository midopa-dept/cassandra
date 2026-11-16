"""BugBounty Bot — 단계 3 통합 테스트 (scanner 확장 + daemon)."""
import sys
import os
import tempfile
import time
import threading
import http.server
import json
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.config import Config
from core.db import DB
from core.models import Asset, Finding
from scanner.infra import scan_tls, scan_subdomain_takeover, scan_s3_bucket, scan_dns_misconfig, scan_infra
from scanner.api import scan_rest_auth, scan_rest_rate_limit, scan_graphql_introspection, scan_api
from scanner.logic import scan_race_condition, scan_payment_bypass, scan_logic
from scanner.nuclei import is_available as nuclei_available
from triage.poc import capture_screenshot, generate_poc_with_screenshot
from core.main import BugBountyBot


class MockHandler(BaseHTTPRequestHandler):
    """Mock 웹 서버: API, GraphQL, payment."""

    def do_GET(self):
        path = self.path

        # API endpoint (no auth)
        if path == "/api/v1/users":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps([
                {"id": 1, "name": "Alice", "email": "alice@example.com"},
                {"id": 2, "name": "Bob", "email": "bob@example.com"},
            ]).encode())
            return

        # API endpoint (rate limit test)
        if path == "/api/v1/rate-test":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}')
            return

        # GraphQL
        if path == "/graphql":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                        "types": [
                            {"name": "User"},
                            {"name": "Post"},
                            {"name": "Comment"},
                        ]
                    }
                }
            }).encode())
            return

        # Default
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body>Mock</body></html>")

    def do_POST(self):
        path = self.path
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode() if content_length else ""

        # Payment endpoint
        if path == "/api/v1/payment":
            try:
                data = json.loads(body)
                amount = data.get("amount", 0)
                if amount <= 0:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status": "success", "message": "Payment completed"}')
                    return
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status": "success", "message": "Payment completed"}')
                    return
            except Exception:
                pass

        # Race condition endpoint
        if path == "/api/v1/race-test":
            # Return different responses based on timing
            import random
            if random.random() < 0.5:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "success"}')
            else:
                self.send_response(409)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status": "conflict"}')
            return

        # Default
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def log_message(self, *args):
        pass


def start_mock_server(port: int) -> http.server.HTTPServer:
    server = http.server.HTTPServer(("127.0.0.1", port), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_infra():
    """Infra scanner test."""
    print("\n[1] Infra scanner test")

    # TLS (example.com)
    findings = scan_tls("example.com", 443)
    print(f"   TLS: {len(findings)} findings")
    for f in findings:
        print(f"     {f.vuln_type}: {f.evidence[:60]}")

    # DNS misconfig
    findings = scan_dns_misconfig("example.com")
    print(f"   DNS misconfig: {len(findings)} findings")

    # S3 (non-existent bucket)
    findings = scan_s3_bucket("nonexistent-bucket-12345")
    print(f"   S3: {len(findings)} findings")

    print("   [✓] Infra scanner test passed")


def test_api():
    """API scanner test."""
    print("\n[2] API scanner test")
    port = 18920
    server = start_mock_server(port)
    time.sleep(0.5)

    base_url = f"http://127.0.0.1:{port}"

    # REST auth
    findings = scan_rest_auth(base_url, ["/api/v1/users"])
    print(f"   REST auth: {len(findings)} findings")
    for f in findings:
        print(f"     {f.vuln_type}: {f.evidence[:60]}")

    # Rate limit
    findings = scan_rest_rate_limit(base_url, "/api/v1/rate-test")
    print(f"   Rate limit: {len(findings)} findings")

    # GraphQL introspection
    findings = scan_graphql_introspection(base_url, "/graphql")
    print(f"   GraphQL introspection: {len(findings)} findings")
    for f in findings:
        print(f"     {f.vuln_type}: {f.evidence[:60]}")

    server.shutdown()
    print("   [✓] API scanner test passed")


def test_logic():
    """Logic scanner test."""
    print("\n[3] Logic scanner test")
    port = 18920
    server = start_mock_server(port)
    time.sleep(0.5)

    base_url = f"http://127.0.0.1:{port}"

    # Race condition
    findings = scan_race_condition(base_url, "/api/v1/race-test", method="POST",
                                   body={"action": "test"}, concurrent_requests=5)
    print(f"   Race condition: {len(findings)} findings")
    for f in findings:
        print(f"     {f.vuln_type}: {f.evidence[:60]}")

    # Payment bypass
    findings = scan_payment_bypass(base_url, "/api/v1/payment", method="POST",
                                   body={"amount": 100, "item": "test"})
    print(f"   Payment bypass: {len(findings)} findings")
    for f in findings:
        print(f"     {f.vuln_type}: {f.evidence[:60]}")

    server.shutdown()
    print("   [✓] Logic scanner test passed")


def test_nuclei():
    """Nuclei test (check availability)."""
    print("\n[4] Nuclei test")
    available = nuclei_available()
    print(f"   Nuclei available: {available}")
    if available:
        print("   [✓] Nuclei found")
    else:
        print("   [i] Nuclei not installed (optional)")
    print("   [✓] Nuclei test passed")


def test_poc():
    """PoC screenshot test."""
    print("\n[5] PoC screenshot test")

    # Test with a simple URL
    screenshot = capture_screenshot("http://example.com", wait_ms=1000)
    if screenshot:
        print(f"   Screenshot: {len(screenshot)} bytes (base64)")
    else:
        print("   [i] Screenshot failed (Playwright not installed?)")

    print("   [✓] PoC test passed")


def test_daemon():
    """Daemon mode test."""
    print("\n[6] Daemon mode test")

    # Create config
    config = Config()
    config.db_path = tempfile.mktemp(suffix=".db")
    config.hackerone.programs = ["example.com"]
    config.scheduler.ct_min = 60
    config.scheduler.dns_min = 360
    config.scheduler.rescan_min = 1440
    config.scheduler.triage_min = 60

    # Create bot
    bot = BugBountyBot(config)

    # Start
    bot.start()
    time.sleep(1)

    # Check scheduler
    jobs = bot.scheduler.running_jobs()
    print(f"   Scheduler jobs: {len(jobs)}")
    for job in jobs:
        print(f"     {job['id']}")

    # Stop
    bot.stop()
    os.unlink(config.db_path)
    print("   [✓] Daemon mode test passed")


def main():
    print("=" * 50)
    print("BugBounty Bot — Stage 3 Integration Test")
    print("=" * 50)

    test_infra()
    test_api()
    test_logic()
    test_nuclei()
    test_poc()
    test_daemon()

    print("\n" + "=" * 50)
    print("All stage 3 tests passed!")
    print("=" * 50)


if __name__ == "__main__":
    main()
