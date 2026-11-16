"""BugBounty Bot — 단계 4 통합 테스트 (track, submit, WebSocket)."""
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
from core.logger import setup_logger
from hackerone.client import HackerOneClient
from hackerone.track import track_reports, get_report_status
from hackerone.submit import auto_submit, submit_report
from web.app import create_app

setup_logger("bugbounty", level=20)


def test_track():
    """HackerOne triage 상태 추적."""
    print("\n[1] HackerOne track test")

    class MockClient(HackerOneClient):
        def __init__(self):
            self.api_key = "test"
            self._reports = {
                "12345": {
                    "state": "triaging",
                    "bounty": 500,
                    "resolved_at": None,
                },
                "67890": {
                    "state": "resolved",
                    "bounty": 1000,
                    "resolved_at": "2026-11-10T12:00:00Z",
                },
            }

        def get_report_status(self, report_id):
            return self._reports.get(report_id)

    client = MockClient()

    # Test get_report_status
    status = get_report_status(client, "12345")
    assert status["state"] == "triaging"
    assert status["bounty"] == 500
    print(f"   Report 12345: {status['state']}, bounty={status['bounty']}")

    status = get_report_status(client, "67890")
    assert status["state"] == "resolved"
    assert status["bounty"] == 1000
    print(f"   Report 67890: {status['state']}, bounty={status['bounty']}")

    print("   [✓] Track test passed")


def test_submit():
    """HackerOne auto-submit."""
    print("\n[2] HackerOne submit test")

    class MockClient(HackerOneClient):
        def __init__(self):
            self.api_key = "test"
            self.client = None  # httpx.Client not needed
            self._submitted = []

        def submit_report(self, program_id, title, description, severity,
                          poc=None, files=None):
            report_id = f"report_{len(self._submitted) + 1}"
            self._submitted.append({
                "id": report_id,
                "program_id": program_id,
                "title": title,
                "severity": severity,
            })
            return report_id

        def create_report(self, report, program_handle):
            report_id = f"report_{len(self._submitted) + 1}"
            self._submitted.append({
                "id": report_id,
                "program_id": program_handle,
                "title": report.title,
                "severity": report.rating,
            })
            return report_id

        def close(self):
            pass

    client = MockClient()

    # Test submit_report
    report_id = submit_report(client, "prog1", "Test Report", "Test description",
                              "high", poc="curl example.com")
    assert report_id == "report_1"
    print(f"   Submitted: {report_id}")

    # Test auto_submit
    db = DB(":memory:")
    asset = Asset(domain="example.com", program="prog1")
    db.save_asset(asset)

    finding = Finding(asset_id=asset.id, vuln_type="sqli", severity="high",
                      endpoint="http://example.com/search?q=test",
                      method="GET", evidence="SQL error",
                      poc_request={"method": "GET", "url": "http://example.com/search?q=test"})
    db.save_finding(finding)

    report = Report(finding_id=finding.id, asset_id=asset.id, program="prog1",
                    title="SQL Injection",
                    summary="SQLi in search", poc="curl example.com/search?q=test",
                    impact="Data breach", recommendation="Use parameterized queries",
                    rating="high", status="draft")
    db.save_report(report)

    # Set auto_submit threshold
    submitted = auto_submit(db, "test_api_key", min_rating="high", client=client)
    assert len(submitted) == 1
    print(f"   Auto-submitted: {len(submitted)} reports")

    print("   [✓] Submit test passed")


def test_websocket():
    """Flask WebSocket."""
    print("\n[3] WebSocket test")

    db = DB(":memory:")
    app, socketio = create_app(db)

    # Test that app and socketio are created
    assert app is not None
    assert socketio is not None
    print("   Flask app + SocketIO created")

    # Test dashboard
    with app.test_client() as client:
        resp = client.get("/")
        assert resp.status_code == 200
        html = resp.data.decode()
        assert "BugBounty Bot" in html
        assert "socket.io" in html  # SocketIO client
        print("   Dashboard: 200 OK (with SocketIO)")

    print("   [✓] WebSocket test passed")


def main():
    print("=" * 50)
    print("BugBounty Bot — Stage 4 Integration Test")
    print("=" * 50)

    test_track()
    test_submit()
    test_websocket()

    print("\n" + "=" * 50)
    print("All stage 4 tests passed!")
    print("=" * 50)


if __name__ == "__main__":
    main()
