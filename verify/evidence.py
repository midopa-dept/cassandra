"""Cassandra — Verifier (감각기관: 재현+증거).

에이전트가 "이게 취약점이다"라고 판단하면,
이 모듈이 재현步骤를 실행하고 before/after 증거를 캡처한다.

출력:
  - 재현 성공/실패
  - before(정상) vs after(취약) 응답 차이
  - HTTP request/response 로그
  - timing
"""
import httpx
import time
import re
from urllib.parse import urljoin
from typing import Optional
from core.config import Config


class Verifier:
    """Finding 재현 + 증거 캡처."""

    def __init__(self, config: Config):
        self.config = config
        self.client = httpx.Client(
            timeout=config.scan.timeout,
            follow_redirects=True,
            headers={"User-Agent": config.scan.user_agent},
        )

    def login(self, base_url: str, login_url: str, username: str, password: str):
        """폼 기반 로그인 (hidden/submit/button 필드 자동 채움, 사용자 필드 자동 감지)."""
        full_url = login_url if login_url.startswith("http") else urljoin(base_url, login_url)
        try:
            r = self.client.get(full_url)
        except Exception:
            return
        data = {}
        for m in re.finditer(r'<input[^>]*type=["\']hidden["\'][^>]*>', r.text, re.IGNORECASE):
            tag = m.group(0)
            name = re.search(r'name=["\']([^"\']*)["\']', tag)
            value = re.search(r'value=["\']([^"\']*)["\']', tag)
            if name:
                data[name.group(1)] = value.group(1) if value else ""
        for m in re.finditer(r'<input[^>]*type=["\']submit["\'][^>]*>', r.text, re.IGNORECASE):
            tag = m.group(0)
            name = re.search(r'name=["\']([^"\']*)["\']', tag)
            value = re.search(r'value=["\']([^"\']*)["\']', tag)
            if name:
                data[name.group(1)] = value.group(1) if value else "submit"
        for m in re.finditer(r'<button[^>]*type=["\']submit["\'][^>]*>', r.text, re.IGNORECASE):
            tag = m.group(0)
            name = re.search(r'name=["\']([^"\']*)["\']', tag)
            if name and name.group(1) not in data:
                data[name.group(1)] = "submit"
        user_field = None
        for m in re.finditer(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', r.text, re.IGNORECASE):
            n = m.group(1).lower()
            if n in ("username", "login", "user", "email", "userid"):
                user_field = m.group(1)
                break
        if not user_field:
            for m in re.finditer(r'<input[^>]*type=["\']text["\'][^>]*name=["\']([^"\']*)["\']', r.text, re.IGNORECASE):
                user_field = m.group(1)
                break
        if not user_field:
            user_field = "username"
        data[user_field] = username
        data["password"] = password
        self.client.post(full_url, data=data)

    def verify(
        self,
        url: str,
        instruction: str,
        expected: Optional[str] = None,
        baseline_url: Optional[str] = None,
        method: Optional[str] = None,
        body: Optional[str] = None,
        headers: Optional[dict] = None,
        baseline_headers: Optional[dict] = None,
    ) -> dict:
        """재현 + 증거.

        Args:
            url: 재현 대상 URL
            instruction: 재현 방법 (에이전트 지시)
            expected: 기대 결과 (pass/fail 판단 기준)
            baseline_url: 비교용 정상 URL (없으면 url 자체를 baseline)
            method: HTTP method (POST 등, 없으면 GET)
            body: request body (method=POST일 때)

        Returns:
            {
                "instruction": ...,
                "reproduced": bool,
                "evidence": {
                    "baseline": {status, body_snippet, time_ms},
                    "exploit": {status, body_snippet, time_ms},
                    "diff": ...,
                },
                "verdict_hint": "confirmed" | "inconclusive" | "refuted",
            }
        """
        # Baseline (always GET the page as-is)
        bl_url = baseline_url or url
        t0 = time.time()
        try:
            bl_resp = self.client.get(bl_url, headers=baseline_headers)
            baseline = {
                "status": bl_resp.status_code,
                "body_snippet": bl_resp.text[:5000],
                "time_ms": round((time.time() - t0) * 1000, 1),
            }
        except Exception as e:
            baseline = {"status": -1, "error": str(e), "body_snippet": "", "time_ms": 0}

        # Exploit (method/body 지정 시 해당 방식으로, 없으면 GET)
        req_method = method.upper() if method else "GET"
        t0 = time.time()
        try:
            if req_method == "POST" and body:
                ex_resp = self.client.post(url, content=body.encode(), headers={"Content-Type": "application/x-www-form-urlencoded", **(headers or {})})
            elif req_method == "POST":
                ex_resp = self.client.post(url, headers=headers)
            else:
                ex_resp = self.client.get(url, headers=headers)
            exploit = {
                "status": ex_resp.status_code,
                "body_snippet": ex_resp.text[:5000],
                "time_ms": round((time.time() - t0) * 1000, 1),
            }
        except Exception as e:
            exploit = {"status": -1, "error": str(e), "body_snippet": "", "time_ms": 0}

        # 판단 힌트 (에이전트가 최종 판단)
        # expected 마커가 exploit body에 있으면 reproduced
        if expected and expected.lower() in exploit.get("body_snippet", "").lower():
            verdict = "confirmed"
            reproduced = True
        elif baseline["status"] != exploit["status"]:
            reproduced = True
            verdict = "confirmed" if (exploit["status"] >= 500 or exploit["status"] in (401, 403)) else "inconclusive"
        else:
            reproduced = False
            verdict = "inconclusive"

        return {
            "instruction": instruction,
            "expected": expected,
            "reproduced": reproduced,
            "evidence": {
                "baseline": baseline,
                "exploit": exploit,
                "diff_snippet": self._diff(baseline.get("body_snippet", ""), exploit.get("body_snippet", "")),
            },
            "verdict_hint": verdict,
        }

    def _diff(self, a: str, b: str, max_len: int = 300) -> str:
        if a == b:
            return "(identical)"
        for i, (ca, cb) in enumerate(zip(a, b)):
            if ca != cb:
                start = max(0, i - 50)
                return f"pos {i}: ...{a[start:i+80]}... VS ...{b[start:i+80]}..."
        longer = b if len(b) > len(a) else a
        shorter_len = min(len(a), len(b))
        return f"(length diff) extra: {longer[shorter_len:shorter_len+max_len]}"
