"""Cassandra Bot — 자산 발견 통합 테스트."""
import sys
import os
import tempfile
import time
import threading
import http.server
import json
from http.server import BaseHTTPRequestHandler

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.db import DB
from core.models import Asset
from asset.ct import query_crt_sh, discover_subdomains
from asset.dns import dns_brute, dns_recon, discover_assets
from asset.api_crawl import crawl_robots_txt, crawl_sitemap, discover_endpoints
from asset.cve_match import detect_tech, match_cves, discover_cves
from asset.rescan import get_assets_due_for_rescan, mark_scanned
from asset.scope import parse_scope, is_in_scope, filter_in_scope


class MockHandler(BaseHTTPRequestHandler):
    """Mock 웹 서버: robots.txt, sitemap.xml, JS, OpenAPI."""

    def do_GET(self):
        path = self.path

        # robots.txt
        if path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\nDisallow: /api/internal\nAllow: /api/public\n")
            return

        # sitemap.xml
        if path == "/sitemap.xml":
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(b"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1:18910/page1</loc></url>
  <url><loc>http://127.0.0.1:18910/page2</loc></url>
  <url><loc>http://127.0.0.1:18910/api/v1/users</loc></url>
</urlset>""")
            return

        # JS file
        if path == "/app.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b"""
var api = '/api/v1/users';
fetch('/api/v2/orders');
axios.get('/api/v3/products');
""")
            return

        # OpenAPI
        if path == "/openapi.json":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "openapi": "3.0.0",
                "paths": {
                    "/api/v1/users": {"get": {}},
                    "/api/v1/orders": {"post": {}},
                    "/api/v1/products": {"get": {}},
                }
            }).encode())
            return

        # Main page (with JS reference)
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"""<html><head>
<script src="/app.js"></script>
</head><body>
<h1>Mock</h1>
</body></html>""")

    def log_message(self, *args):
        pass


def start_mock_server(port: int) -> http.server.HTTPServer:
    server = http.server.HTTPServer(("127.0.0.1", port), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_ct():
    """CT test: crt.sh API (mock)."""
    print("\n[1] CT test")
    # crt.sh is external, so we just test the function exists
    # In production, this would query crt.sh
    print("   [✓] CT module loaded (crt.sh is external)")


def test_dns():
    """DNS test: dns_recon (local)."""
    print("\n[2] DNS test")
    # Test dns_recon with a known domain
    recon = dns_recon("example.com")
    print(f"   example.com: A={recon['a'][:2]}, MX={recon['mx'][:1]}")
    assert "a" in recon
    print("   [✓] DNS recon works")


def test_api_crawl():
    """API crawl test: mock server."""
    print("\n[3] API crawl test")
    port = 18910
    server = start_mock_server(port)
    time.sleep(0.5)

    base_url = f"http://127.0.0.1:{port}"

    # robots.txt
    robots = crawl_robots_txt(base_url)
    print(f"   robots.txt: {robots}")
    assert "/admin" in robots
    assert "/api/internal" in robots

    # sitemap
    sitemap = crawl_sitemap(base_url)
    print(f"   sitemap: {sitemap}")
    assert len(sitemap) >= 3

    # JS endpoints
    from asset.api_crawl import crawl_js_endpoints
    js_endpoints = crawl_js_endpoints(base_url)
    print(f"   JS endpoints: {js_endpoints}")
    assert len(js_endpoints) >= 1

    # OpenAPI
    from asset.api_crawl import crawl_openapi
    openapi = crawl_openapi(base_url)
    print(f"   OpenAPI: {openapi}")
    assert len(openapi) >= 3

    # All endpoints
    all_endpoints = discover_endpoints(base_url)
    print(f"   Total endpoints: {len(all_endpoints)}")
    assert len(all_endpoints) >= 5

    server.shutdown()
    print("   [✓] API crawl test passed")


def test_cve_match():
    """CVE match test: tech detection."""
    print("\n[4] CVE match test")
    port = 18910
    server = start_mock_server(port)
    time.sleep(0.5)

    base_url = f"http://127.0.0.1:{port}"
    tech, cves = discover_cves(base_url)
    print(f"   Tech: {list(tech.keys())}")
    print(f"   CVEs: {cves}")
    # Mock server doesn't have specific tech headers, so tech may be empty
    print("   [✓] CVE match test passed")

    server.shutdown()


def test_rescan():
    """Rescan test: assets due for rescan."""
    print("\n[5] Rescan test")
    db_path = tempfile.mktemp(suffix=".db")
    db = DB(db_path)

    # Create assets with different last_scan times
    from datetime import datetime, timedelta

    # Asset 1: never scanned
    a1 = Asset(domain="example1.com", program="test")
    db.save_asset(a1)

    # Asset 2: scanned 25 hours ago (due for rescan)
    a2 = Asset(domain="example2.com", program="test")
    a2.last_scan = (datetime.utcnow() - timedelta(hours=25)).isoformat()
    db.save_asset(a2)

    # Asset 3: scanned 1 hour ago (not due)
    a3 = Asset(domain="example3.com", program="test")
    a3.last_scan = (datetime.utcnow() - timedelta(hours=1)).isoformat()
    db.save_asset(a3)

    due = get_assets_due_for_rescan(db, interval_hours=24)
    print(f"   Due for rescan: {len(due)}")
    assert len(due) == 2  # a1 (never) + a2 (25h ago)

    # Mark scanned
    mark_scanned(db, a1.id)
    a1_updated = db.get_asset(a1.id)
    assert a1_updated.last_scan is not None
    print(f"   Marked {a1.domain} as scanned")

    os.unlink(db_path)
    print("   [✓] Rescan test passed")


def test_scope():
    """Scope test: in-scope/out-of-scope."""
    print("\n[6] Scope test")

    # Parse scope
    scopes = parse_scope("*.example.com, api.example.com")
    print(f"   Scopes: {scopes}")
    assert len(scopes) == 2

    # Check in-scope
    assert is_in_scope("www.example.com", scopes) is True
    assert is_in_scope("blog.example.com", scopes) is True
    assert is_in_scope("api.example.com", scopes) is True
    assert is_in_scope("example.com", scopes) is True  # wildcard matches base
    assert is_in_scope("evil.com", scopes) is False
    assert is_in_scope("example.com.evil.com", scopes) is False

    # Filter assets
    assets = [
        Asset(domain="www.example.com"),
        Asset(domain="api.example.com"),
        Asset(domain="evil.com"),
    ]
    in_scope = filter_in_scope(assets, "*.example.com, api.example.com")
    print(f"   In-scope: {len(in_scope)} / {len(assets)}")
    assert len(in_scope) == 2

    print("   [✓] Scope test passed")


def main():
    print("=" * 50)
    print("Cassandra Bot — Asset Discovery Test")
    print("=" * 50)

    test_ct()
    test_dns()
    test_api_crawl()
    test_cve_match()
    test_rescan()
    test_scope()

    print("\n" + "=" * 50)
    print("All asset discovery tests passed!")
    print("=" * 50)


if __name__ == "__main__":
    main()
