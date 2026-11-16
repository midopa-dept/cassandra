"""BugBounty Bot — 실전 테스트: DVWA + Juice Shop scanner."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.models import Asset
from asset.crawl import crawl, crawl_api
from scanner.web import scan_web
from scanner.api import scan_api
from scanner.infra import scan_infra
from scanner.logic import scan_logic
from scanner.login import login, get_authenticated_client
from core.logger import setup_logger

log = setup_logger("test_live")


def test_target(name: str, base_url: str, use_login: bool = False):
    """단일 타겟 테스트: crawl → scan → findings 출력."""
    print(f"\n{'='*60}")
    print(f"  {name} — {base_url}")
    print(f"{'='*60}")

    # 1. Crawl (with authenticated client if login)
    print(f"\n[1] Crawling...")
    auth_client = None
    if use_login:
        asset_tmp = Asset(base_url=base_url)
        auth_client = get_authenticated_client(asset_tmp)
        endpoints = crawl(base_url, max_pages=20, max_depth=2, client=auth_client)
        api_endpoints = crawl_api(base_url, client=auth_client)
    else:
        endpoints = crawl(base_url, max_pages=20, max_depth=2)
        api_endpoints = crawl_api(base_url)
    all_endpoints = endpoints + api_endpoints
    print(f"    Found {len(endpoints)} web + {len(api_endpoints)} API endpoints")

    for ep in all_endpoints[:10]:
        params_str = f" params={ep.params}" if ep.params else ""
        forms_str = f" forms={len(ep.forms)}" if ep.forms else ""
        print(f"    - {ep.url}{params_str}{forms_str}")
    if len(all_endpoints) > 10:
        print(f"    ... and {len(all_endpoints)-10} more")

    # 2. Login (if needed) — already done in crawl step
    if use_login:
        print(f"\n[2] Login: authenticated client used for crawl")
    else:
        print(f"\n[2] No login needed")

    # 3. Scan (use authenticated client if login)
    print(f"\n[3] Scanning...")
    asset = Asset(base_url=base_url, endpoints=all_endpoints)
    findings = scan_web(asset, client=auth_client)
    # API scan (NoSQLi, admin registration, OpenAPI, REST body)
    api_findings = scan_api(asset)
    findings.extend(api_findings)
    # 6e: Infra (TLS, subdomain takeover, S3, DNS) + Logic (race, payment, workflow)
    infra_findings = scan_infra(asset)
    findings.extend(infra_findings)
    logic_findings = scan_logic(asset)
    findings.extend(logic_findings)

    # 4. Results
    print(f"\n[4] Results: {len(findings)} findings")
    by_type = {}
    for f in findings:
        by_type.setdefault(f.vuln_type, []).append(f)

    for vuln_type, items in sorted(by_type.items()):
        print(f"\n  {vuln_type} ({len(items)}):")
        for f in items[:5]:
            print(f"    [{f.severity}] {f.endpoint} — {f.evidence[:100]}")
        if len(items) > 5:
            print(f"    ... and {len(items)-5} more")

    return findings


if __name__ == "__main__":
    total = 0

    # DVWA (login required)
    dvwa_findings = test_target("DVWA", "http://localhost:8081", use_login=True)
    total += len(dvwa_findings)

    # Juice Shop
    juice_findings = test_target("Juice Shop", "http://localhost:3000")
    total += len(juice_findings)

    print(f"\n{'='*60}")
    print(f"  TOTAL: {total} findings")
    print(f"{'='*60}")
