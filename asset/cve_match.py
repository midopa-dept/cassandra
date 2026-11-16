"""BugBounty Bot — CVE 매칭 (Wappalyzer + NVD)."""
import httpx
import re
from typing import Optional
from core.models import Asset
from core.logger import get_logger

log = get_logger("asset.cve_match")

# Wappalyzer-like tech detection (simplified)
TECH_PATTERNS = {
    "nginx": [r"Server:\s*nginx", r"X-Powered-By:\s*nginx"],
    "apache": [r"Server:\s*Apache", r"X-Powered-By:\s*Apache"],
    "iis": [r"Server:\s*Microsoft-IIS", r"X-AspNet-Version"],
    "php": [r"X-Powered-By:\s*PHP", r"Set-Cookie:\s*PHPSESSID"],
    "aspnet": [r"X-AspNet-Version", r"Set-Cookie:\s*ASP\.NET_SessionId"],
    "node": [r"X-Powered-By:\s*Express", r"X-Node-Version"],
    "ruby": [r"X-Powered-By:\s*Rack", r"Server:\s*thin"],
    "python": [r"X-Powered-By:\s*WSGI", r"Server:\s*Werkzeug"],
    "react": [r"__NEXT_DATA__", r"react-root", r"__react"],
    "vue": [r"__vue__", r"vue-app"],
    "angular": [r"ng-app", r"angularjs"],
    "jquery": [r"jquery[.-]\d"],
    "bootstrap": [r"bootstrap[.-]\d"],
    "wordpress": [r"wp-content", r"wp-includes", r"WordPress"],
    "drupal": [r"Drupal", r"drupal-settings-json"],
    "joomla": [r"Joomla", r"joomla"],
    "shopify": [r"Shopify", r"shopify"],
    "magento": [r"Magento", r"magento"],
    "elasticsearch": [r"X-elastic", r"elasticsearch"],
    "redis": [r"X-Redis", r"redis"],
    "mongodb": [r"MongoDB", r"mongodb"],
    "mysql": [r"X-MySQL", r"mysql"],
    "postgres": [r"X-Postgres", r"postgres"],
    "cloudflare": [r"Server:\s*cloudflare", r"CF-RAY"],
    "aws": [r"X-Amz-", r"aws"],
    "azure": [r"X-AspNet", r"azure"],
    "gcp": [r"X-Goog", r"google"],
}

# NVD API
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def detect_tech(base_url: str, client: Optional[httpx.Client] = None) -> dict[str, str]:
    """Wappalyzer-like: HTTP headers + HTML에서 기술 스택 탐지."""
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=15, follow_redirects=True)

    try:
        resp = client.get(base_url)
        headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
        body = resp.text

        tech = {}
        for name, patterns in TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, headers_str, re.IGNORECASE) or re.search(pattern, body, re.IGNORECASE):
                    tech[name] = "detected"
                    break

        return tech
    except Exception:
        return {}
    finally:
        if own_client:
            client.close()


def query_nvd(cve_id: str, client: Optional[httpx.Client] = None) -> Optional[dict]:
    """NVD API: CVE 조회."""
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=30)

    try:
        resp = client.get(NVD_API_URL, params={"cveId": cve_id})
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return vulns[0]
        return None
    except Exception:
        return None
    finally:
        if own_client:
            client.close()


def match_cves(tech_stack: dict[str, str]) -> list[str]:
    """기술 스택 → 관련 CVE 매칭 (simplified)."""
    # In production, this would query NVD with product/version
    # For now, return known CVEs for detected tech
    cves = []

    # Example: if WordPress detected, check for known WP CVEs
    if "wordpress" in tech_stack:
        cves.extend([
            "CVE-2023-37424",  # WP Core SQLi
            "CVE-2023-37920",  # WP Core auth bypass
        ])

    # Example: if Apache detected
    if "apache" in tech_stack:
        cves.extend([
            "CVE-2021-41773",  # Apache HTTP Server 2.4.49 RCE
            "CVE-2021-42013",  # Apache HTTP Server 2.4.49 RCE
        ])

    # Example: if Nginx detected
    if "nginx" in tech_stack:
        cves.extend([
            "CVE-2021-23017",  # Nginx off-by-one
        ])

    return cves


def discover_cves(base_url: str) -> tuple[dict[str, str], list[str]]:
    """기술 스택 탐지 + CVE 매칭."""
    tech = detect_tech(base_url)
    cves = match_cves(tech)

    log.info(f"CVE match: {base_url} → tech={list(tech.keys())}, cves={len(cves)}")
    return tech, cves
