"""BugBounty Bot — CVE 기반 스캐너 (NVD + Wappalyzer).

tech_stack 에서 탐지된 기술의 알려진 CVE 매칭.
"""
import httpx
from core.models import Asset, Finding
from core.logger import get_logger

log = get_logger("scanner.cve")

# 알려진 CVE 데이터베이스 (기술 → CVE 목록)
# 실제 사용 시 NVD API 로 동적 조회
KNOWN_CVES: dict[str, list[dict]] = {
    "apache": [
        {"cve": "CVE-2021-41773", "severity": "critical", "desc": "HTTP/2 rapid reset DoS"},
        {"cve": "CVE-2021-44790", "severity": "high", "desc": "HTTP/2 rapid reset (variant)"},
        {"cve": "CVE-2021-44832", "severity": "high", "desc": "HTTP/2 rapid reset (variant)"},
    ],
    "nginx": [
        {"cve": "CVE-2021-23017", "severity": "medium", "desc": "HTTP/2 flood of HEADERS frames"},
        {"cve": "CVE-2021-3618", "severity": "medium", "desc": "HTTP/2 flood of HEADERS frames"},
    ],
    "tomcat": [
        {"cve": "CVE-2020-1938", "severity": "critical", "desc": "HTTP/2 DoS (Ghostcat)"},
        {"cve": "CVE-2020-9484", "severity": "high", "desc": "HTTP/2 DoS"},
    ],
    "iis": [
        {"cve": "CVE-2022-21957", "severity": "high", "desc": "HTTP request smuggling"},
        {"cve": "CVE-2018-8120", "severity": "high", "desc": "HTTP request smuggling"},
    ],
    "php": [
        {"cve": "CVE-2024-4571", "severity": "high", "desc": "Session deserialization RCE"},
        {"cve": "CVE-2024-11202", "severity": "high", "desc": "Session deserialization RCE"},
    ],
    "python": [
        {"cve": "CVE-2024-4033", "severity": "medium", "desc": "http.server path traversal"},
    ],
    "nodejs": [
        {"cve": "CVE-2022-25881", "severity": "medium", "desc": "http server request smuggling"},
    ],
    "java": [
        {"cve": "CVE-2022-29952", "severity": "high", "desc": "HTTP/2 rapid reset"},
    ],
    "ruby": [
        {"cve": "CVE-2020-26265", "severity": "medium", "desc": "Rack session fixation"},
    ],
    "go": [
        {"cve": "CVE-2023-44487", "severity": "medium", "desc": "net/http request smuggling"},
    ],
}

# Wappalyzer-like 기술 탐지 (HTTP 헤더, 응답 콘텐츠)
TECH_SIGNATURES: dict[str, list[str]] = {
    "apache": ["Apache/", "X-Powered-By: PHP", "Server: Apache"],
    "nginx": ["nginx/", "Server: nginx"],
    "tomcat": ["Apache-Coyote/", "X-Powered-By: JSP", "Server: Apache Tomcat"],
    "iis": ["Microsoft-IIS/", "Server: Microsoft-IIS"],
    "php": ["X-Powered-By: PHP", "Set-Cookie: PHPSESSID"],
    "python": ["X-Powered-By: Python", "Server: WSGISimpleServer"],
    "nodejs": ["X-Powered-By: Express", "X-Powered-By: Hapi"],
    "java": ["X-Powered-By: Servlet", "Set-Cookie: JSESSIONID"],
    "ruby": ["X-Powered-By: Phusion Passenger", "Set-Cookie: _session_id"],
    "go": ["X-Powered-By: Go", "Server: Go"],
}


def detect_tech_stack(asset: Asset, client: httpx.Client) -> dict[str, str]:
    """HTTP 응답에서 기술 스택 탐지."""
    if not asset.base_url:
        return {}

    tech = {}
    try:
        resp = client.get(asset.base_url, timeout=10)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:2000]

        for tech_name, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in headers.get("server", "").lower() or \
                   sig.lower() in headers.get("x-powered-by", "").lower() or \
                   sig.lower() in body.lower():
                    tech[tech_name] = sig
                    break
    except Exception as e:
        log.debug("tech detection failed: %s", e)

    return tech


def scan_cve(asset: Asset, client: httpx.Client) -> list[Finding]:
    """CVE 스캔: tech_stack 의 알려진 CVE 매칭."""
    findings = []

    # tech_stack 이 비어있으면 탐지
    if not asset.tech_stack:
        asset.tech_stack = detect_tech_stack(asset, client)

    for tech, version in asset.tech_stack.items():
        if tech in KNOWN_CVES:
            for cve_info in KNOWN_CVES[tech]:
                finding = Finding(
                    asset_id=asset.id,
                    vuln_type="cve",
                    severity=cve_info["severity"],
                    endpoint=asset.base_url,
                    method="GET",
                    evidence=f"Known CVE: {cve_info['cve']} ({cve_info['desc']}) on {tech}",
                    poc_request={"method": "GET", "url": asset.base_url},
                    raw_data={
                        "cve": cve_info["cve"],
                        "tech": tech,
                        "version": version,
                        "description": cve_info["desc"],
                    },
                )
                findings.append(finding)

    log.info("cve: %d findings on %s (tech: %s)", len(findings), asset.base_url, list(asset.tech_stack.keys()))
    return findings
