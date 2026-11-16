"""BugBounty Bot — Fuzzing / Anomaly 스캐너.

unknown 버그 탐지: 응답 길이, 상태 코드, 헤더, 콘텐츠 타입 이상.
"""
import httpx
import random
import string
from core.models import Asset, Endpoint, Finding
from core.logger import get_logger

log = get_logger("scanner.fuzz")

# Fuzzing payload 들
FUZZ_PAYLOADS = [
    # Boundary values
    ("", "empty"),
    (" ", "whitespace"),
    ("a" * 1000, "long-string"),
    ("a" * 10000, "very-long-string"),
    ("-" * 100, "negative-repeat"),
    # Special characters
    ("\\", "backslash"),
    ("\\n", "newline"),
    ("\\r\\n", "crlf"),
    ("\\t", "tab"),
    ("\\0", "null-byte"),
    ("\\x01", "control-char"),
    ("\\xff", "high-byte"),
    # Unicode
    ("é", "accented"),
    ("日本語", "cjk"),
    ("🎉", "emoji"),
    ("\\u0000", "unicode-null"),
    # SQL/NoSQL injection hints
    ("'\";--", "sql-mix"),
    ("{}$ne:1", "nosql"),
    ("[1,2,3]", "array"),
    ("{a:1}", "object"),
    # Path traversal
    ("../", "dot-dot-slash"),
    ("..\\", "dot-dot-backslash"),
    ("/etc/passwd", "etc-passwd"),
    ("\\\\windows\\system32", "windows-path"),
    # HTTP smuggling hints
    ("\\r\\nX-Injected: 1", "header-injection"),
    ("\\r\\n\\r\\nGET / HTTP/1.1", "request-smuggling"),
    # XML/JSON
    ("<?xml version=\"1.0\"?>", "xml-decl"),
    ("{\"$gt\":\"\"}", "json-regex"),
    ("[[[", "nested-array"),
    # Format string
    ("%n%n%n%n", "format-string"),
    ("%s%s%s%s", "format-string-s"),
    ("%x%x%x%x", "format-string-x"),
]

# Anomaly detection thresholds
LENGTH_ANOMALY_FACTOR = 3.0  # baseline 대비 3배 이상
STATUS_ANOMALIES = {500, 502, 503, 504}  # 서버 오류


def scan_fuzz(asset: Asset, endpoint: Endpoint, client: httpx.Client) -> list[Finding]:
    """Fuzzing 스캔: 각 파라미터에 다양한 payload 주입, 이상 응답 탐지."""
    findings = []
    if not endpoint.params:
        return findings

    base_url = endpoint.url or asset.base_url

    # Baseline
    baseline = _request(client, base_url, endpoint.method, {})
    if baseline is None:
        return findings

    baseline_len = len(baseline.text)

    for param in endpoint.params:
        for payload, technique in FUZZ_PAYLOADS:
            params = {param: payload}
            resp = _request(client, base_url, endpoint.method, params)
            if resp is None:
                continue

            # Anomaly 1: status code
            if resp.status_code in STATUS_ANOMALIES and baseline.status_code == 200:
                finding = Finding(
                    asset_id=asset.id,
                    vuln_type="fuzz_anomaly",
                    severity="medium",
                    endpoint=base_url,
                    method=endpoint.method,
                    evidence=f"Status anomaly: baseline=200, payload='{payload[:50]}'→{resp.status_code} (technique: {technique})",
                    poc_request={"method": endpoint.method, "url": base_url, "params": params},
                    raw_data={"technique": technique, "baseline_status": baseline.status_code, "payload_status": resp.status_code},
                )
                findings.append(finding)

            # Anomaly 2: response length
            if baseline_len > 0 and len(resp.text) > baseline_len * LENGTH_ANOMALY_FACTOR:
                finding = Finding(
                    asset_id=asset.id,
                    vuln_type="fuzz_anomaly",
                    severity="low",
                    endpoint=base_url,
                    method=endpoint.method,
                    evidence=f"Length anomaly: baseline={baseline_len}, payload='{payload[:50]}'→{len(resp.text)} (technique: {technique})",
                    poc_request={"method": endpoint.method, "url": base_url, "params": params},
                    raw_data={"technique": technique, "baseline_len": baseline_len, "payload_len": len(resp.text)},
                )
                findings.append(finding)

            # Anomaly 3: error messages in response
            error_patterns = ["traceback", "exception", "error:", "fatal:", "panic:", "segfault", "core dump"]
            body_lower = resp.text.lower()
            for pattern in error_patterns:
                if pattern in body_lower and pattern not in baseline.text.lower():
                    finding = Finding(
                        asset_id=asset.id,
                        vuln_type="fuzz_anomaly",
                        severity="medium",
                        endpoint=base_url,
                        method=endpoint.method,
                        evidence=f"Error pattern '{pattern}' appeared with payload='{payload[:50]}' (technique: {technique})",
                        poc_request={"method": endpoint.method, "url": base_url, "params": params},
                        raw_data={"technique": technique, "pattern": pattern},
                    )
                    findings.append(finding)
                    break

    log.info("fuzz: %d findings on %s", len(findings), base_url)
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
