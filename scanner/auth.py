"""Cassandra Bot — Auth Bypass 스캐너."""
import httpx
from core.models import Asset, Endpoint, Finding
from core.logger import get_logger

log = get_logger("scanner.auth")

AUTH_BYPASS_TECHNIQUES = [
    # HTTP method override
    ("X-HTTP-Method-Override", "POST", "GET"),
    ("X-Method-Override", "POST", "GET"),
    ("X-HTTP-Method", "POST", "GET"),
    # Case manipulation
    ("X-Forwarded-Method", "GET", "POST"),
    # Path traversal
    ("..;/", "path-traversal", None),
    (".%2e/", "encoded-dot", None),
    ("/./", "dot-path", None),
    # Header-based bypass
    ("X-Original-URL", "/admin", None),
    ("X-Rewrite-URL", "/admin", None),
    ("X-Custom-Id", "/admin", None),
    # Auth header removal
    ("Authorization-Remove", None, None),
    # Cookie manipulation
    ("Cookie-Remove", None, None),
]


def scan_auth_bypass(asset: Asset, endpoint: Endpoint, client: httpx.Client) -> list[Finding]:
    """Auth bypass 스캔: 인증 우회 기법 테스트."""
    findings = []
    base_url = endpoint.url or asset.base_url

    # Baseline: request without auth
    baseline = _request_no_auth(client, base_url, endpoint.method)
    if baseline is None:
        return findings

    # If baseline is 401/403, try bypass techniques
    if baseline.status_code in (401, 403):
        for header_name, value, technique in AUTH_BYPASS_TECHNIQUES:
            if value is None and technique is None:
                # Remove auth headers
                resp = _request_no_auth(client, base_url, endpoint.method)
            elif technique:
                # Path manipulation
                modified_url = base_url + technique
                resp = _request_no_auth(client, modified_url, endpoint.method)
            else:
                # Add override header
                resp = _request_with_header(client, base_url, endpoint.method, header_name, value)

            if resp is not None and resp.status_code == 200 and baseline.status_code in (401, 403):
                finding = Finding(
                    asset_id=asset.id,
                    vuln_type="auth_bypass",
                    severity="high",
                    endpoint=base_url,
                    method=endpoint.method,
                    evidence=f"Auth bypass: {header_name}={value} returned 200 (baseline was {baseline.status_code})",
                    poc_request={
                        "method": endpoint.method,
                        "url": base_url,
                        "headers": {header_name: value} if value else {},
                    },
                    raw_data={"technique": technique or header_name, "baseline_status": baseline.status_code, "bypass_status": resp.status_code},
                )
                findings.append(finding)

    log.info("auth_bypass: %d findings on %s", len(findings), base_url)
    return findings


def _request_no_auth(client: httpx.Client, url: str, method: str) -> httpx.Response | None:
    try:
        if method.upper() == "GET":
            return client.get(url, timeout=10)
        elif method.upper() == "POST":
            return client.post(url, timeout=10)
        return client.get(url, timeout=10)
    except Exception as e:
        log.debug("request failed: %s %s: %s", method, url, e)
        return None


def _request_with_header(client: httpx.Client, url: str, method: str, header: str, value: str) -> httpx.Response | None:
    try:
        headers = {header: value}
        if method.upper() == "GET":
            return client.get(url, headers=headers, timeout=10)
        elif method.upper() == "POST":
            return client.post(url, headers=headers, timeout=10)
        return client.get(url, headers=headers, timeout=10)
    except Exception as e:
        log.debug("request failed: %s %s: %s", method, url, e)
        return None
