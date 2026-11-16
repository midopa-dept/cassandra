"""BugBounty Bot — 웹 앱 스캐너 orchestrator.

각 scanner (sqli, xss, idor, ssrf, auth) 를 호출해서 findings 수집.
"""
import httpx
from core.models import Asset, Finding
from core.logger import get_logger
from scanner.sqli import scan_sqli
from scanner.xss import scan_xss
from scanner.idor import scan_idor
from scanner.ssrf import scan_ssrf
from scanner.auth import scan_auth_bypass
from scanner.fuzz import scan_fuzz

log = get_logger("scanner.web")


def scan_web(asset: Asset) -> list[Finding]:
    """웹 앱 스캔: asset.endpoints 를 순회하며 각 scanner 실행."""
    findings = []
    if not asset.base_url:
        log.warning("scan_web: no base_url for asset %s", asset.id)
        return findings

    client = httpx.Client(base_url=asset.base_url, follow_redirects=True)

    for endpoint in asset.endpoints:
        # 각 scanner 실행
        findings.extend(scan_sqli(asset, endpoint, client))
        findings.extend(scan_xss(asset, endpoint, client))
        findings.extend(scan_idor(asset, endpoint, client))
        findings.extend(scan_ssrf(asset, endpoint, client))
        findings.extend(scan_auth_bypass(asset, endpoint, client))
        findings.extend(scan_fuzz(asset, endpoint, client))

    client.close()
    log.info("scan_web: %d total findings on %s", len(findings), asset.base_url)
    return findings
