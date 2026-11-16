"""Cassandra Bot — 웹 앱 스캐너 orchestrator.

각 scanner (sqli, xss, idor, ssrf, auth) 를 호출해서 findings 수집.
"""
import httpx
from core.models import Asset, Finding
from core.logger import get_logger
from scanner.sqli import scan_sqli
from scanner.xss import scan_xss, scan_dom_xss, scan_stored_xss
from scanner.idor import scan_idor
from scanner.ssrf import scan_ssrf
from scanner.file import scan_file
from scanner.auth import scan_auth_bypass
from scanner.fuzz import scan_fuzz
from scanner.cve import scan_cve
from scanner.session import scan_session

log = get_logger("scanner.web")


def scan_web(asset: Asset, client: httpx.Client | None = None) -> list[Finding]:
    """웹 앱 스캔: asset.endpoints 를 순회하며 각 scanner 실행.

    client: 인증 클라이언트 (login 필요 앱). 없으면 비인증 클라이언트 생성.
    """
    findings = []
    if not asset.base_url:
        log.warning("scan_web: no base_url for asset %s", asset.id)
        return findings

    close_client = False
    if client is None:
        client = httpx.Client(base_url=asset.base_url, follow_redirects=True)
        close_client = True

    for endpoint in asset.endpoints:
        # 각 scanner 실행
        findings.extend(scan_sqli(asset, endpoint, client))
        findings.extend(scan_xss(asset, endpoint, client))
        findings.extend(scan_stored_xss(asset, endpoint, client))
        findings.extend(scan_idor(asset, endpoint, client))
        findings.extend(scan_ssrf(asset, endpoint, client))
        findings.extend(scan_file(asset, endpoint, client))
        findings.extend(scan_auth_bypass(asset, endpoint, client))
        findings.extend(scan_fuzz(asset, endpoint, client))

    # DOM XSS (asset 단위: JS 번들 분석)
    findings.extend(scan_dom_xss(asset, client))

    # CVE 스캔 (endpoint 없이 asset 단위)
    findings.extend(scan_cve(asset, client))

    # 6d: 인증/세션 (weak_session, captcha, password_reset) — asset 단위
    findings.extend(scan_session(asset, client))

    if close_client:
        client.close()
    log.info("scan_web: %d total findings on %s", len(findings), asset.base_url)
    return findings
