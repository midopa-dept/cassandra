"""BugBounty Bot — XSS 스캐너."""
import httpx
from core.models import Asset, Endpoint, Finding
from core.logger import get_logger

log = get_logger("scanner.xss")

XSS_PAYLOADS = [
    ('<script>alert("xss")</script>', "reflected-script"),
    ('<img src=x onerror=alert(1)>', "reflected-img"),
    ('<svg onload=alert(1)>', "reflected-svg"),
    ('" onmouseover="alert(1)', "attribute-break"),
    ("'><script>alert(1)</script>", "quote-break"),
    ('javascript:alert(1)', "js-pseudo-protocol"),
    ('<body onload=alert(1)>', "body-onload"),
    ('<input autofocus onfocus=alert(1)>', "input-onfocus"),
]

XSS_INDICATORS = [
    "<script>alert",
    "onerror=alert",
    "onload=alert",
    "onmouseover=alert",
    "onfocus=alert",
    "javascript:alert",
]


def scan_xss(asset: Asset, endpoint: Endpoint, client: httpx.Client) -> list[Finding]:
    """XSS 스캔: 각 파라미터에 payload 주입, 응답에 payload가 그대로 반영되는지 확인."""
    findings = []
    if not endpoint.params:
        return findings

    base_url = endpoint.url or asset.base_url

    for param in endpoint.params:
        for payload, technique in XSS_PAYLOADS:
            params = {p: (payload if p == param else p) for p in endpoint.params}
            resp = _request(client, base_url, endpoint.method, params)
            if resp is None:
                continue

            body = resp.text
            # Check if payload is reflected unencoded
            for indicator in XSS_INDICATORS:
                if indicator in body:
                    # Verify it's not inside a <script> tag that's properly escaped
                    if "&lt;" not in body.split(indicator)[0][-50:]:
                        finding = Finding(
                            asset_id=asset.id,
                            vuln_type="xss",
                            severity="medium",
                            endpoint=base_url,
                            method=endpoint.method,
                            evidence=f"XSS payload reflected: '{indicator}' in response (technique: {technique})",
                            poc_request={
                                "method": endpoint.method,
                                "url": base_url,
                                "params": params,
                            },
                            raw_data={"technique": technique, "status": resp.status_code},
                        )
                        findings.append(finding)
                        break

    log.info("xss: %d findings on %s", len(findings), base_url)
    return findings


def _request(client: httpx.Client, url: str, method: str, params: dict) -> httpx.Response | None:
    try:
        if method.upper() == "GET":
            return client.get(url, params=params, timeout=10)
        elif method.upper() == "POST":
            return client.post(url, data=params, timeout=10)
        return client.get(url, params=params, timeout=10)
    except Exception as e:
        log.debug("request failed: %s %s: %s", method, url, e)
        return None
