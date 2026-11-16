"""Cassandra — 통합 테스트 (MVP).

도구(감각기관) 테스트:
  [1] ScannerContext: mock 서버 관찰 → 구조화 JSON (forms/endpoints/patterns)
  [2] ExploitExecutor: exploit 지시 실행 → 결과 캡처 + signals
  [3] Verifier: 재현 → before/after 증거
  [4] pattern scanners: scan_web으로 SQLi/XSS/IDOR 발견
"""
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
from core.models import Asset, Finding, Endpoint
from scanner.context import ScannerContext
from scanner.web import scan_web
from exploit.executor import ExploitExecutor
from verify.evidence import Verifier


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

        # Login form page
        if path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<html><body>
            <form action="/login" method="POST">
              <input type="text" name="username" placeholder="user"/>
              <input type="password" name="password" autocomplete="current-password"/>
              <button>Login</button>
            </form>
            </body></html>""")
            return

        # Default
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html><body><h1>Mock Server</h1></body></html>")

    def log_message(self, format, *args):
        pass


def start_mock_server(port: int) -> http.server.HTTPServer:
    server = http.server.HTTPServer(("127.0.0.1", port), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_scanner_context():
    """ScannerContext: mock 서버 관찰 → 구조화 데이터."""
    print("\n[1] ScannerContext test")
    port = 18901
    server = start_mock_server(port)
    time.sleep(0.5)

    cfg = Config.load()
    ctx = ScannerContext(cfg)
    result = ctx.scan(f"http://127.0.0.1:{port}/login", max_pages=5)

    print(f"   pages_scanned={result['pages_scanned']}")
    print(f"   summary={json.dumps(result['summary'], ensure_ascii=False)}")

    # login 페이지의 폼을 관찰했는가
    forms_found = False
    for p in result["pages"]:
        for f in p.get("forms", []):
            field_names = [fld["name"] for fld in f["fields"]]
            if "username" in field_names and "password" in field_names:
                forms_found = True
    assert forms_found, "login form not observed"
    print("   [✓] login form observed (username/password)")

    server.shutdown()
    print("   [✓] ScannerContext test passed")


def test_exploit_executor():
    """ExploitExecutor: SQLi payload 실행 → sql_error signal."""
    print("\n[2] ExploitExecutor test")
    port = 18902
    server = start_mock_server(port)
    time.sleep(0.5)

    cfg = Config.load()
    ex = ExploitExecutor(cfg)

    # 정상 요청 (baseline)
    baseline = ex._do_request("GET", f"http://127.0.0.1:{port}/search?q=test", {}, None)
    # exploit 요청
    result = ex.execute(
        url=f"http://127.0.0.1:{port}/search",
        instruction="q 파라미터에 ' OR 1=1-- (SQLi)",
        method="GET",
        compare_with=f"http://127.0.0.1:{port}/search?q=test",
    )
    # params를 body에 넣어 다시 (execute는 body만, query는 url에)
    result2 = ex.execute(
        url=f"http://127.0.0.1:{port}/search?q=%27%20OR%201%3D1--",
        instruction="q=' OR 1=1--",
        method="GET",
    )
    print(f"   signals={result2['signals']}")
    print(f"   status={result2['response']['status']}")
    assert "sql_error" in result2["signals"], f"expected sql_error, got {result2['signals']}"

    server.shutdown()
    print("   [✓] ExploitExecutor test passed")


def test_verifier():
    """Verifier: 재현 → before/after 증거."""
    print("\n[3] Verifier test")
    port = 18903
    server = start_mock_server(port)
    time.sleep(0.5)

    cfg = Config.load()
    v = Verifier(cfg)
    result = v.verify(
        url=f"http://127.0.0.1:{port}/search?q=%27%20OR%201%3D1--",
        instruction="q=' OR 1=1-- (SQLi 재현)",
        baseline_url=f"http://127.0.0.1:{port}/search?q=test",
    )
    print(f"   reproduced={result['reproduced']} verdict_hint={result['verdict_hint']}")
    print(f"   evidence keys={list(result['evidence'].keys())}")
    assert "baseline" in result["evidence"]
    assert "exploit" in result["evidence"]

    server.shutdown()
    print("   [✓] Verifier test passed")


def test_pattern_scanners():
    """pattern scanners: scan_web으로 SQLi/XSS/IDOR 발견."""
    print("\n[4] Pattern scanner test")
    port = 18904
    server = start_mock_server(port)
    time.sleep(0.5)

    asset = Asset(
        domain=f"127.0.0.1:{port}",
        base_url=f"http://127.0.0.1:{port}",
        endpoints=[
            Endpoint(url=f"http://127.0.0.1:{port}/search", params=["q"]),
            Endpoint(url=f"http://127.0.0.1:{port}/api/user/1", params=["id"]),
        ],
        program="test",
    )

    findings = scan_web(asset)
    vuln_types = set(f.vuln_type for f in findings)
    print(f"   Found {len(findings)} findings, types={vuln_types}")
    assert len(findings) > 0, "no findings"

    server.shutdown()
    print("   [✓] Pattern scanner test passed")


def main():
    print("=" * 50)
    print("Cassandra — Integration Test")
    print("=" * 50)

    test_scanner_context()
    test_exploit_executor()
    test_verifier()
    test_pattern_scanners()

    print("\n" + "=" * 50)
    print("All tests passed!")
    print("=" * 50)


if __name__ == "__main__":
    main()
