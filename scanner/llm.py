"""BugBounty Bot — LLM 스캐너 (7b).

정적 scanner(패턴 매칭)와 달리, LLM이 페이지를 *이해*해서
맥락에 맞는 공격을 계획·실행·판정한다.

3단계 (엔드포인트당):
  1. 분석  : 페이지 HTML + 폼 필드 → LLM → JSON 테스트 계획
  2. 실행  : 계획의 각 항목을 httpx로 실제로 요청
  3. 검증  : 실행 결과 → LLM → 진짜 취약점인가? (Finding)

비용 통제: 엔드포인트당 LLM 호출 2회, 엔드포인트 수 상한(MAX_ENDPOINTS).
LLM 호출 실패는 스킵(정적 scanner가 베이스라인을 커버).
"""
import json
import re
import httpx
from core.models import Asset, Endpoint, Finding
from core.logger import get_logger
from triage.llm import LLMClient

log = get_logger("scanner.llm")

# 엔드포인트 상한 (LLM 호출 비용 통제)
MAX_ENDPOINTS = 8
# 페이지 HTML 잘림 상한 (토큰 통제)
MAX_HTML_CHARS = 6000
# 실행 결과 잘림 상한
MAX_RESULT_CHARS = 2000

PLAN_PROMPT = """You are a security researcher testing a web application.
Analyze this page and plan concrete security tests.

Page URL: {url}
HTTP status: {status}
Form fields: {fields}
HTML (truncated):
{html}

Plan up to 3 concrete tests for the most likely vulnerabilities on THIS page
(SQLi, XSS, IDOR, auth bypass, SSRF, injection, etc.).
For each test, give the exact request to send.

Respond with JSON only:
{{"tests": [
  {{"vuln_type": "sqli|xss|idor|ssrf|auth_bypass|injection|other",
    "method": "GET|POST",
    "url": "full URL",
    "params": {{"field": "payload"}},
    "body": "form body or empty",
    "expect": "what response signal proves the vuln"}}
]}}
If the page has no testable input, respond {{"tests": []}}.
"""

VERIFY_PROMPT = """You are a security researcher verifying a test result.

Test: {vuln_type} on {url}
Expected signal: {expect}
Request: {method} {url} {params} {body}
Response status: {status}
Response body (truncated):
{resp_body}

Is the vulnerability confirmed? Judge strictly — only confirm if the response
clearly shows the expected signal (error message, reflected payload, data
leak, etc.). Do not confirm on weak or ambiguous evidence.

Respond with JSON only:
{{"confirmed": true/false, "severity": "low|medium|high|critical",
  "evidence": "the specific part of the response that proves it"}}
"""


def _extract_json(text: str) -> dict:
    """LLM 응답에서 JSON 추출 (```json 블록 포함 처리)."""
    m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if m:
        text = m.group(1)
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end])
        except json.JSONDecodeError:
            pass
    return {}


def _page_summary(client: httpx.Client, url: str) -> tuple[int, str]:
    """페이지 GET → (status, html). redirect를 따라가고, 3xx는 200으로 처리."""
    try:
        r = client.get(url, timeout=10, follow_redirects=True)
        status = r.status_code
        if status in (301, 302, 303, 307, 308):
            status = 200
        return status, r.text
    except Exception:
        return 0, ""


def _execute_test(client: httpx.Client, test: dict, base_url: str) -> tuple[int, str]:
    """테스트 계획 1개 실행 → (status, body)."""
    method = test.get("method", "GET").upper()
    url = test.get("url", "")
    if not url.startswith("http"):
        url = base_url.rstrip("/") + "/" + url.lstrip("/")
    params = test.get("params") or {}
    body = test.get("body") or ""
    try:
        if method == "POST":
            if body and not params:
                r = client.post(url, content=body, timeout=10)
            else:
                r = client.post(url, data=params, timeout=10)
        else:
            r = client.get(url, params=params, timeout=10)
        return r.status_code, r.text
    except Exception as e:
        return 0, f"request error: {e}"


def scan_llm_endpoint(asset: Asset, endpoint: Endpoint, client: httpx.Client,
                      llm: LLMClient) -> list[Finding]:
    """엔드포인트 1개: 분석 → 실행 → 검증."""
    findings = []
    url = endpoint.url
    if not url:
        return findings

    status, html = _page_summary(client, url)
    if status == 0 or not html:
        return findings

    fields = []
    for f in (endpoint.forms or []):
        fields.extend(f.get("fields") or [])

    # 1. 분석: 테스트 계획
    try:
        plan_resp = llm.chat([{
            "role": "user",
            "content": PLAN_PROMPT.format(
                url=url, status=status,
                fields=", ".join(fields) or "(none)",
                html=html[:MAX_HTML_CHARS],
            ),
        }], temperature=0.2)
    except Exception as e:
        log.debug(f"LLM plan failed for {url}: {e}")
        return findings

    plan = _extract_json(plan_resp)
    tests = plan.get("tests") or []
    if not tests:
        return findings

    # 2. 실행 + 3. 검증
    for test in tests[:3]:
        vuln_type = test.get("vuln_type", "other")
        if vuln_type not in ("sqli", "xss", "idor", "ssrf", "auth_bypass",
                             "injection", "other"):
            vuln_type = "other"
        t_status, t_body = _execute_test(client, test, asset.base_url)

        try:
            verify_resp = llm.chat([{
                "role": "user",
                "content": VERIFY_PROMPT.format(
                    vuln_type=vuln_type, url=test.get("url", url),
                    expect=test.get("expect", ""),
                    method=test.get("method", "GET"),
                    params=json.dumps(test.get("params") or {}),
                    body=(test.get("body") or "")[:500],
                    status=t_status,
                    resp_body=t_body[:MAX_RESULT_CHARS],
                ),
            }], temperature=0.1)
        except Exception as e:
            log.debug(f"LLM verify failed for {url}: {e}")
            continue

        verdict = _extract_json(verify_resp)
        if not verdict.get("confirmed"):
            continue

        findings.append(Finding(
            asset_id=asset.id,
            vuln_type=f"llm_{vuln_type}",
            endpoint=url,
            method=test.get("method", "GET").upper(),
            severity=verdict.get("severity", "medium"),
            evidence=f"LLM: {verdict.get('evidence', '')}".strip("LLM: "),
            poc_request={
                "method": test.get("method", "GET").upper(),
                "url": test.get("url", url),
                "params": test.get("params") or {},
                "body": test.get("body") or "",
            },
        ))
    return findings


def scan_llm(asset: Asset, client: httpx.Client,
             llm: LLMClient | None = None) -> list[Finding]:
    """LLM 스캐너: 엔드포인트를 분석→테스트→판정.

    llm 미지정이면 LLMConfig(OPENAI_API_KEY)로 생성. 키 없으면 스킵.
    """
    findings = []
    if llm is None:
        from core.config import Config
        cfg = Config.load()
        if not cfg.llm.api_key:
            log.debug("LLM scanner skipped: no API key")
            return findings
        llm = LLMClient(provider=cfg.llm.provider, model=cfg.llm.model,
                        api_key=cfg.llm.api_key)

    # 폼이 있는 엔드포인트 우선 (입력면이 있는 곳)
    endpoints = sorted(
        [e for e in (asset.endpoints or []) if e.url],
        key=lambda e: 0 if e.forms else 1,
    )[:MAX_ENDPOINTS]

    for ep in endpoints:
        findings.extend(scan_llm_endpoint(asset, ep, client, llm))

    if findings:
        log.info(f"LLM scanner: {len(findings)} findings")
    return findings
