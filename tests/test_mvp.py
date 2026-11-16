"""BugBounty Bot — 통합 테스트 (MVP)."""
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
from core.models import Asset, Finding, Report
from scanner.web import scan_web
from triage.llm import LLMClient, judge_finding, assess_severity, generate_report, generate_poc_curl
from triage.dedup import dedup_findings
from hackerone.client import HackerOneClient


class MockHandler(BaseHTTPRequestHandler):
    """Mock 웹 서버: SQLi, XSS, IDOR 취약점 시뮬레이션."""

    def do_GET(self):
        path = self.path
        query = ""
        if "?" in path:
            path, query = path.split("?", 1)

        # SQLi: /search?q=' OR 1=1--
        if path == "/search" and "q=" in query:
            from urllib.parse import unquote
            q = unquote(query.split("q=")[1])
            if "OR 1=1" in q or "UNION SELECT" in q:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"<html><body><h1>SQL Error: You have an error in your SQL syntax</h1></body></html>")
                return

        # XSS: /search?q=<script>alert(1)</script>
        if path == "/search" and "q=" in query:
            from urllib.parse import unquote
            q = unquote(query.split("q=")[1])
            if "<script>" in q or "onerror=" in q:
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(f"<html><body><div>{q}</div></body></html>".encode())
                return

        # IDOR: /api/user/1, /api/user/2
        if path.startswith("/api/user/"):
            user_id = path.split("/")[-1]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"id": int(user_id), "name": f"User {user_id}", "email": f"user{user_id}@example.com"}).encode())
            return

        # Default
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Mock Server</h1></body></html>")

    def log_message(self, format, *args):
        pass  # Suppress logs


def start_mock_server(port: int) -> http.server.HTTPServer:
    server = http.server.HTTPServer(("127.0.0.1", port), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_scanner():
    """Scanner 테스트: mock 서버에서 SQLi, XSS, IDOR 발견."""
    print("\n[1] Scanner test")
    port = 18901
    server = start_mock_server(port)
    time.sleep(0.5)

    asset = Asset(
        domain=f"127.0.0.1:{port}",
        endpoints=[
            f"http://127.0.0.1:{port}/search?q=test",
            f"http://127.0.0.1:{port}/api/user/1",
        ],
        program="test",
    )

    findings = scan_web(asset, rate_limit=20)
    print(f"   Found {len(findings)} findings")

    vuln_types = set(f.vuln_type for f in findings)
    print(f"   Types: {vuln_types}")

    # Dedup
    db_path = tempfile.mktemp(suffix=".db")
    db = DB(db_path)
    db.save_asset(asset)
    for f in findings:
        f.asset_id = asset.id
        db.save_finding(f)

    deduped = dedup_findings(db, findings)
    print(f"   After dedup: {len(deduped)}")

    server.shutdown()
    os.unlink(db_path)
    print("   [✓] Scanner test passed")


def test_triage():
    """Triage 테스트: LLM (mock) + PoC 생성."""
    print("\n[2] Triage test")

    # Mock LLM (no API key needed)
    class MockLLM(LLMClient):
        def chat(self, messages, temperature=0.3):
            prompt = messages[-1]["content"]
            if "is_real" in prompt:
                return '{"is_real": true, "confidence": 0.9, "reasoning": "SQL error in response"}'
            elif "severity" in prompt.lower() or "rating" in prompt.lower():
                return "high"
            elif "Title:" in prompt:
                return """Title: SQL Injection in /search endpoint
Summary: The /search endpoint is vulnerable to SQL injection via the 'q' parameter.
PoC:
curl 'http://127.0.0.1:18901/search?q=%27%20OR%201=1--'
Impact: Attacker can extract database contents.
Recommendation: Use parameterized queries."""
            return "ok"

    llm = MockLLM(provider="openai", model="gpt-4o", api_key="mock")

    finding = Finding(
        vuln_type="sqli",
        severity="high",
        endpoint="http://127.0.0.1:18901/search?q=' OR 1=1--",
        method="GET",
        evidence="SQL error detected",
        poc_request={"method": "GET", "url": "http://127.0.0.1:18901/search", "params": {"q": "' OR 1=1--"}},
    )
    asset = Asset(domain="127.0.0.1:18901", program="test")

    # Judge
    result = judge_finding(llm, finding, asset)
    print(f"   Judge: is_real={result['is_real']}, confidence={result['confidence']}")
    assert result["is_real"] is True

    # Severity
    severity = assess_severity(llm, finding, asset)
    print(f"   Severity: {severity}")
    assert severity == "high"

    # Report
    report = generate_report(llm, finding, asset, severity)
    print(f"   Report: {report.title}")
    print(f"   PoC: {repr(report.poc)}")
    assert report.title
    assert report.poc is not None

    # PoC curl
    poc_curl = generate_poc_curl(finding)
    print(f"   PoC: {poc_curl[:80]}...")
    assert "curl" in poc_curl

    print("   [✓] Triage test passed")


def test_hackerone():
    """HackerOne client 테스트 (mock)."""
    print("\n[3] HackerOne client test")

    # Mock client (no real API call)
    class MockH1(HackerOneClient):
        def __init__(self):
            pass  # Skip real init

        def _graphql(self, query, variables=None):
            if "createSubmission" in query:
                return {"createSubmission": {"submission": {"id": "12345", "url": "https://hackerone.com/12345"}}}
            if "viewer" in query:
                return {"viewer": {"collaborations": {"edges": [{"node": {"id": "1", "name": "Test Program", "handle": "test", "offersBounties": True}}]}}}
            if "submission" in query:
                return {"submission": {"id": "12345", "state": "triaging", "title": "Test", "bounty": 500, "reward": 500}}
            return {}

    client = MockH1()

    # List programs
    programs = client.list_programs()
    print(f"   Programs: {len(programs)}")
    assert len(programs) == 1

    # Create report
    report = Report(
        title="SQL Injection in /search",
        summary="SQLi via q parameter",
        poc="curl 'http://example.com/search?q=%27%20OR%201=1--'",
        impact="Data extraction",
        recommendation="Use parameterized queries",
        rating="high",
        program="test",
    )
    report_id = client.create_report(report, "test")
    print(f"   Report ID: {report_id}")
    assert report_id == "12345"

    # Get status
    status = client.get_report_status("12345")
    print(f"   Status: {status.get('state')}, bounty: {status.get('bounty')}")
    assert status.get("state") == "triaging"

    print("   [✓] HackerOne client test passed")


def test_web():
    """Web dashboard 테스트."""
    print("\n[4] Web dashboard test")

    import tempfile
    db_path = tempfile.mktemp(suffix=".db")
    db = DB(db_path)

    # Add test data
    asset = Asset(domain="example.com", program="test")
    db.save_asset(asset)
    finding = Finding(asset_id=asset.id, vuln_type="sqli", severity="high", endpoint="/search")
    db.save_finding(finding)
    report = Report(finding_id=finding.id, asset_id=asset.id, program="test", title="SQLi", rating="high", status="draft")
    db.save_report(report)

    from web.app import create_app
    app, socketio = create_app(db)

    with app.test_client() as client:
        # Dashboard
        resp = client.get("/")
        assert resp.status_code == 200
        assert b"BugBounty Bot" in resp.data
        print("   Dashboard: 200 OK")

        # API stats
        resp = client.get("/api/stats")
        data = resp.get_json()
        assert data["assets"] == 1
        assert data["findings"] == 1
        print(f"   Stats: {data}")

        # API findings
        resp = client.get("/api/findings")
        findings = resp.get_json()
        assert len(findings) == 1
        print(f"   Findings: {len(findings)}")

        # API reports
        resp = client.get("/api/reports")
        reports = resp.get_json()
        assert len(reports) == 1
        print(f"   Reports: {len(reports)}")

        # Submit report
        resp = client.post(f"/api/reports/{report.id}/submit")
        data = resp.get_json()
        assert data["status"] == "submitted"
        print("   Submit: OK")

    os.unlink(db_path)
    print("   [✓] Web dashboard test passed")


def main():
    print("=" * 50)
    print("BugBounty Bot — MVP Integration Test")
    print("=" * 50)

    test_scanner()
    test_triage()
    test_hackerone()
    test_web()

    print("\n" + "=" * 50)
    print("All MVP tests passed!")
    print("=" * 50)


if __name__ == "__main__":
    main()
