"""8d: 정적 vs LLM scanner 비교."""
import sys, json
sys.path.insert(0, '.')
from core.models import Asset
from scanner.llm import scan_llm
from scanner.sqli import scan_sqli
from scanner.xss import scan_xss, scan_stored_xss
from scanner.idor import scan_idor
from scanner.ssrf import scan_ssrf
from scanner.file import scan_file
from scanner.auth import scan_auth_bypass
from scanner.fuzz import scan_fuzz
from scanner.login import get_authenticated_client
from asset.crawl import crawl

class MockLLM:
    def chat(self, messages, temperature=0.2):
        p = messages[0]['content']
        if 'Plan up to 3' in p:
            return json.dumps({"tests": [
                {"vuln_type": "sqli", "method": "POST",
                 "url": "http://localhost:8082/vuln/sqli/",
                 "params": {}, "body": "id=1%20OR%201=1",
                 "content_type": "form", "expect": "SQL error"},
                {"vuln_type": "xss", "method": "POST",
                 "url": "http://localhost:8082/vuln/xss/",
                 "params": {}, "body": "name=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                 "content_type": "form", "expect": "XSS reflected"},
            ]})
        return json.dumps({"confirmed": True, "severity": "high",
                           "evidence": "SQL error in response"})

def scan_static_only(asset, client):
    f = []
    for ep in asset.endpoints:
        f.extend(scan_sqli(asset, ep, client))
        f.extend(scan_xss(asset, ep, client))
        f.extend(scan_stored_xss(asset, ep, client))
        f.extend(scan_idor(asset, ep, client))
        f.extend(scan_ssrf(asset, ep, client))
        f.extend(scan_file(asset, ep, client))
        f.extend(scan_auth_bypass(asset, ep, client))
        f.extend(scan_fuzz(asset, ep, client))
    return f

for name, url in [("bWAPP", "http://localhost:8082"),
                  ("WebGoat", "http://localhost:8083/WebGoat")]:
    asset = Asset(base_url=url)
    client = get_authenticated_client(asset)
    eps = crawl(url, client=client, max_pages=20, max_depth=2)
    asset.endpoints = eps
    static_f = scan_static_only(asset, client)
    llm_f = scan_llm(asset, client, MockLLM())
    print(f"\n=== {name} ===")
    print(f"endpoints: {len(eps)}")
    print(f"static: {len(static_f)} findings")
    for f in static_f:
        print(f"  [{f.severity}] {f.vuln_type} @ {f.endpoint}")
    print(f"LLM: {len(llm_f)} findings")
    for f in llm_f:
        print(f"  [{f.severity}] {f.vuln_type} @ {f.endpoint}")
