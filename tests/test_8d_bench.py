"""8d: bWAPP + WebGoat LLM scanner 실측 (Mock LLM)."""
import sys, json
sys.path.insert(0, '.')
from core.models import Asset
from scanner.llm import scan_llm
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
                 "content_type": "form",
                 "expect": "SQL error"},
                {"vuln_type": "xss", "method": "POST",
                 "url": "http://localhost:8082/vuln/xss/",
                 "params": {}, "body": "name=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                 "content_type": "form",
                 "expect": "XSS reflected"},
            ]})
        return json.dumps({"confirmed": True, "severity": "high",
                           "evidence": "SQL error in response"})

for name, url in [("bWAPP", "http://localhost:8082"),
                  ("WebGoat", "http://localhost:8083/WebGoat")]:
    asset = Asset(base_url=url)
    client = get_authenticated_client(asset)
    eps = crawl(url, client=client, max_pages=20, max_depth=2)
    asset.endpoints = eps
    print(f"\n=== {name} ({url}) ===")
    print(f"endpoints: {len(eps)}")
    for e in eps:
        print(f"  {e.url}")
    findings = scan_llm(asset, client, MockLLM())
    print(f"LLM findings: {len(findings)}")
    for f in findings:
        print(f"  [{f.severity}] {f.vuln_type} @ {f.endpoint}")
