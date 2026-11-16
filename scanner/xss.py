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


# ── DOM XSS (JS 번들 sink 분석) ───────────────────────────────────────

# DOM sink: 사용자 입력(location/document.URL)을 DOM에 쓰는 함수
DOM_SINKS = [
    "innerHTML",
    "outerHTML",
    "document.write",
    "document.writeln",
    "insertAdjacentHTML",
    "insertBefore",
    "eval(",
    "window.open(",
    "location.replace(",
    "location.assign(",
]

# source: DOM sink에 들어가는 사용자 제어 입력
DOM_SOURCES = [
    "location.hash",
    "location.search",
    "location.href",
    "document.URL",
    "document.location",
    "window.name",
]


def scan_dom_xss(asset: Asset, client: httpx.Client) -> list[Finding]:
    """DOM XSS: HTML에서 JS 번들 추출 → sink(innerHTML 등)가 source(location 등)를
    읽는지 정적 분석. sink+source가 같은 번들에 있으면 DOM XSS 공격면 신호."""
    findings = []
    base_url = asset.base_url
    if not base_url:
        return findings

    try:
        resp = client.get(base_url, timeout=15)
    except Exception:
        return findings
    if resp.status_code != 200:
        return findings

    # HTML에서 JS 번들 URL 추출
    import re
    js_urls = re.findall(r'src="([^"]+\.js)"', resp.text)
    # inline script도 분석
    inline_scripts = re.findall(r'<script(?![^>]*src=)[^>]*>(.*?)</script>', resp.text, re.DOTALL)

    seen = set()
    for js_url in js_urls:
        if js_url in seen:
            continue
        seen.add(js_url)
        if js_url.startswith("/"):
            full = base_url.rstrip("/") + js_url
        elif js_url.startswith("http"):
            full = js_url
        else:
            full = base_url.rstrip("/") + "/" + js_url
        try:
            r = client.get(full, timeout=15)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        code = r.text
        sinks = [s for s in DOM_SINKS if s in code]
        sources = [s for s in DOM_SOURCES if s in code]
        if sinks and sources:
            finding = Finding(
                asset_id=asset.id,
                vuln_type="dom_xss",
                severity="medium",
                endpoint=full,
                method="GET",
                evidence=f"DOM XSS sink({', '.join(sinks[:3])}) + source({', '.join(sources[:3])}) in JS bundle",
                poc_request={"method": "GET", "url": full},
                raw_data={"sinks": sinks, "sources": sources, "size": len(code)},
            )
            findings.append(finding)

    # inline script 분석
    for code in inline_scripts:
        if len(code) < 20:
            continue
        sinks = [s for s in DOM_SINKS if s in code]
        sources = [s for s in DOM_SOURCES if s in code]
        if sinks and sources:
            finding = Finding(
                asset_id=asset.id,
                vuln_type="dom_xss",
                severity="medium",
                endpoint=base_url,
                method="GET",
                evidence=f"DOM XSS sink({', '.join(sinks[:3])}) + source({', '.join(sources[:3])}) in inline script",
                poc_request={"method": "GET", "url": base_url},
                raw_data={"sinks": sinks, "sources": sources},
            )
            findings.append(finding)

    log.info("dom_xss: %d findings on %s", len(findings), base_url)
    return findings


# ── Stored XSS (POST 저장 → GET 반사) ─────────────────────────────────

STORED_XSS_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<script>alert("xss")</script>',
]


def scan_stored_xss(asset: Asset, endpoint: Endpoint, client: httpx.Client) -> list[Finding]:
    """Stored XSS: 폼 필드에 XSS payload를 POST로 저장 → 같은 페이지 GET에서
    payload가 인코딩 없이 반사되는지 확인. (예: DVWA xss_s 등)"""
    findings = []
    if not endpoint.forms:
        return findings

    base_url = endpoint.url or asset.base_url

    for form in endpoint.forms:
        action = form.get("action", "")
        fields = form.get("fields", [])
        if not fields:
            continue
        # action이 상대경로면 base_url에 붙임
        if action.startswith("/"):
            post_url = base_url.split("/vulnerabilities")[0].rstrip("/") + action if "/vulnerabilities" in base_url else base_url.rstrip("/") + action
        elif action.startswith("http"):
            post_url = action
        else:
            post_url = base_url

        for field_name in fields:
            # 버튼/hidden 필드는 스킵
            if field_name.lower() in ("submit", "btnsign", "btnclear", "login", "user_token"):
                continue
            for payload in STORED_XSS_PAYLOADS:
                data = {f: (payload if f == field_name else "test") for f in fields}
                # Submit 버튼 포함 (일부 앱은 버튼 없으면 처리 안 함)
                if "btnSign" in fields:
                    data["btnSign"] = "Sign"
                try:
                    client.post(post_url, data=data, timeout=10)
                except Exception:
                    continue
                # 저장 후 GET에서 반사 확인
                try:
                    r = client.get(base_url, timeout=10)
                except Exception:
                    continue
                if r.status_code == 200 and payload in r.text:
                    finding = Finding(
                        asset_id=asset.id,
                        vuln_type="stored_xss",
                        severity="high",
                        endpoint=base_url,
                        method="POST",
                        evidence=f"Stored XSS: payload in field '{field_name}' reflected unencoded on GET",
                        poc_request={"method": "POST", "url": post_url, "data": data},
                        raw_data={"field": field_name, "payload": payload},
                    )
                    findings.append(finding)
                    break  # 이 필드는 하나면 충분

    log.info("stored_xss: %d findings on %s", len(findings), base_url)
    return findings
