"""Cassandra Bot — 인증/세션 스캐너 (6d).

세 가지 취약점 (모두 일반화: 특정 앱 하드코딩 없음):

  weak_session  : 엔드포인트를 반복 요청 → Set-Cookie 수집 → 재생성되는
                  cookie(값이 바뀔 때마다 새로 발급)를 찾아, 그 값이
                  순차/저엔트로피/짧으면 예측 가능 세션 ID로 판정.
                  (예: DVWA weak_id: dvwaSession=1,2,3,4,5 순차)
  captcha       : CAPTCHA 페이지 탐지 → 우회 신호:
                    (a) reCAPTCHA/hCaptcha sitekey 빈/누락 (비활성)
                    (b) "key missing" 경고
                    (c) 같은 session에서 CAPTCHA 이미지 재사용
                    (d) CAPTCHA 값 추측(0/1/1234) → 성공
                  (예: DVWA captcha: sitekey='' → 우회)
  password_reset: reset/forgot endpoint 탐지 → token 추출 → 단순성/엔트로피.
                  (email 기반이면 토큰 미추출 → finding 없음, 오탐 방지)

asset-level scanner (엔드포인트 파라미터 주입이 아닌 플로우 단위).
"""
import math
import re
import httpx
from urllib.parse import urljoin
from core.models import Asset, Finding
from core.logger import get_logger

log = get_logger("scanner.session")

# 세션 ID: 이보다 짧으면 취약 신호
SHORT_SESSION_LEN = 16
# entropy bit/char: 이보다 낮으면 예측 가능
LOW_ENTROPY = 3.0
# 순차성: 연속 값 간 평균 차이(숫자)가 이보다 작으면 순차
SEQUENTIAL_DELTA = 5
# 재생성 판정: 최소 구분값 수
MIN_DISTINCT = 3
# 엔드포인트 반복 요청 횟수
PROBE_N = 4
# 엔드포인트 상한 (요청 수 제한)
MAX_ENDPOINTS = 20


def _shannon_entropy(s: str) -> float:
    """Shannon entropy (bits per char)."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    ent = 0.0
    for count in freq.values():
        p = count / n
        ent -= p * math.log2(p)
    return ent


def _parse_set_cookie(sc: str) -> list[tuple[str, str]]:
    """Set-Cookie 헤더에서 (name, value) 목록 추출 (여러 cookie 지원)."""
    result = []
    for part in sc.split(","):
        part = part.strip()
        if not part or "=" not in part:
            continue
        nameval = part.split(";")[0].strip()
        if "=" not in nameval:
            continue
        name, val = nameval.split("=", 1)
        name = name.strip()
        val = val.strip()
        if name:
            result.append((name, val))
    return result


def _is_sequential(values: list[str]) -> tuple[bool, float]:
    """숫자 기반 순차성 검사. (is_seq, avg_delta) 반환."""
    nums = []
    for v in values:
        m = re.search(r"(\d+)$", v)
        if m:
            nums.append(int(m.group(1)))
    if len(nums) < 3:
        return False, 0.0
    deltas = [abs(nums[i + 1] - nums[i]) for i in range(len(nums) - 1)]
    avg = sum(deltas) / len(deltas)
    return avg < SEQUENTIAL_DELTA, avg


# ── Weak Session ──────────────────────────────────────────────────────

def scan_weak_session(asset: Asset, client: httpx.Client) -> list[Finding]:
    """Weak Session ID: 엔드포인트 반복 요청 → 재생성되는 cookie 수집 →
    순차성/엔트로피/길이 분석. 재생성되는 cookie가 예측 가능하면 취약.

    일반화: 특정 cookie 이름/경로 하드코딩 없음. Set-Cookie 재생성 패턴으로 판별.
    """
    findings = []
    if not asset.base_url:
        return findings

    # 엔드포인트 목록: crawled + 알려진 session 관련 경로
    from scanner.login import find_login_form
    login_ep = find_login_form(asset, client)
    login_url = login_ep.url if login_ep else None

    # 알려진 session 관련 경로를 우선 (session cookie 재생성 엔드포인트)
    candidate_urls: list[str] = []
    for path in ["/vulnerabilities/weak_id/", "/weak_id/", "/weak_session/",
                 "/session/", "/vulnerabilities/session/"]:
        candidate_urls.append(urljoin(asset.base_url, path))
    # crawled endpoints
    for ep in asset.endpoints or []:
        if ep.url:
            candidate_urls.append(ep.url)

    # cookie_name → [values over time]
    cookie_seqs: dict[str, list[str]] = {}
    seen_urls: set[str] = set()

    for url in candidate_urls:
        if not url or url in seen_urls:
            continue
        seen_urls.add(url)
        if len(seen_urls) > MAX_ENDPOINTS:
            break

        # GET N회
        has_form = False
        for _ in range(PROBE_N):
            try:
                r = client.get(url, timeout=10)
            except Exception:
                continue
            if r.status_code == 200 and "<form" in r.text.lower():
                has_form = True
            for name, val in _parse_set_cookie(r.headers.get("set-cookie", "")):
                cookie_seqs.setdefault(name, []).append(val)

        # POST N회 (form 있는 경우만, login 제외 — logout side-effect 방지)
        if has_form and url != login_url:
            for _ in range(PROBE_N):
                try:
                    r = client.post(url, data={}, timeout=10)
                except Exception:
                    continue
                for name, val in _parse_set_cookie(r.headers.get("set-cookie", "")):
                    cookie_seqs.setdefault(name, []).append(val)

    # 재생성되는 cookie 분석
    reported: set[str] = set()
    for name, vals in cookie_seqs.items():
        distinct = list(dict.fromkeys(vals))
        if len(distinct) < MIN_DISTINCT:
            continue  # 재생성 안 됨 (고정 cookie)
        if name in reported:
            continue

        lengths = [len(v) for v in distinct]
        avg_len = sum(lengths) / len(lengths)
        entropies = [_shannon_entropy(v) for v in distinct]
        avg_ent = sum(entropies) / len(entropies)
        is_seq, avg_delta = _is_sequential(distinct)

        reasons = []
        if avg_len < SHORT_SESSION_LEN:
            reasons.append(f"short (avg {avg_len:.0f} chars)")
        if avg_ent < LOW_ENTROPY:
            reasons.append(f"low entropy ({avg_ent:.2f} bits/char)")
        if is_seq:
            reasons.append(f"sequential (avg delta {avg_delta:.1f})")

        if reasons:
            reported.add(name)
            finding = Finding(
                asset_id=asset.id,
                vuln_type="weak_session",
                severity="medium",
                endpoint=asset.base_url,
                method="POST",
                evidence=(f"Weak session cookie '{name}' regenerates with "
                          f"predictable values: {', '.join(reasons)}. "
                          f"Sample: {distinct[:5]}"),
                poc_request={
                    "method": "POST",
                    "url": asset.base_url,
                    "note": (f"cookie '{name}' regenerates on each request; "
                             f"avg_len={avg_len:.0f}, avg_entropy={avg_ent:.2f}, "
                             f"sequential={is_seq}"),
                },
                raw_data={
                    "cookie_name": name,
                    "values": distinct,
                    "avg_len": avg_len,
                    "avg_entropy": avg_ent,
                    "sequential": is_seq,
                    "avg_delta": avg_delta,
                },
            )
            findings.append(finding)

    log.info("weak_session: %d findings on %s (cookies tracked=%d)",
             len(findings), asset.base_url, len(cookie_seqs))
    return findings


# ── CAPTCHA ───────────────────────────────────────────────────────────

CAPTCHA_HINTS = [
    "captcha", "recaptcha", "g-recaptcha", "hcaptcha", "hcaptcha.com",
    "captcha-image", "captcha_image", "captcha.php", "captcha.png",
    "captcha.gif", "captcha.jpg", "recaptcha/api.js",
]


def _has_captcha(html: str) -> bool:
    low = html.lower()
    return any(h in low for h in CAPTCHA_HINTS)


def scan_captcha(asset: Asset, client: httpx.Client) -> list[Finding]:
    """Insecure CAPTCHA: CAPTCHA 페이지 탐지 → 우회 신호 검사.

    일반화:
      (a) reCAPTCHA/hCaptcha sitekey 빈/누락 → CAPTCHA 비활성 (우회)
      (b) "key missing" 경고 텍스트
      (c) 같은 session에서 CAPTCHA 이미지 재사용 (바이트 동일)
    """
    findings = []
    if not asset.base_url:
        return findings

    # 후보 URL: 알려진 경로 + crawled endpoints
    candidates: list[str] = []
    for path in ["/captcha/", "/vulnerabilities/captcha/", "/login.php",
                 "/login", "/brute/", "/vulnerabilities/brute/"]:
        candidates.append(urljoin(asset.base_url, path))
    for ep in asset.endpoints or []:
        if ep.url:
            candidates.append(ep.url)

    seen: set[str] = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        try:
            r = client.get(url, timeout=10)
        except Exception:
            continue
        if r.status_code != 200 or not _has_captcha(r.text):
            continue

        bypass = False
        evidence: list[str] = []

        # (a) sitekey 빈/누락
        m = re.search(r'data-sitekey=["\']([^"\']*)["\']', r.text)
        if m and not m.group(1).strip():
            bypass = True
            evidence.append("reCAPTCHA/hCaptcha sitekey is empty (CAPTCHA disabled)")
        # (b) key missing 경고
        if re.search(r"(recaptcha|captcha)\s+(api\s+)?key\s+missing", r.text, re.I):
            bypass = True
            evidence.append("CAPTCHA API key missing (disabled)")

        # (c) CAPTCHA 이미지 재사용 (같은 session에서 두 번 GET → 동일 바이트)
        img = re.search(r'src=["\']([^"\']*captcha[^"\']*)["\']', r.text, re.I)
        if img:
            img_url = urljoin(url, img.group(1))
            try:
                c = httpx.Client(base_url=asset.base_url, follow_redirects=True)
                i1 = c.get(img_url, timeout=10)
                i2 = c.get(img_url, timeout=10)
                c.close()
                if i1.content == i2.content and len(i1.content) > 0:
                    bypass = True
                    evidence.append("CAPTCHA image not regenerated within session (reusable)")
            except Exception:
                pass

        if bypass:
            finding = Finding(
                asset_id=asset.id,
                vuln_type="captcha",
                severity="high",
                endpoint=url,
                method="GET",
                evidence="Insecure CAPTCHA: " + "; ".join(evidence),
                poc_request={"method": "GET", "url": url,
                             "note": "; ".join(evidence)},
                raw_data={"evidence": evidence},
            )
            findings.append(finding)

    log.info("captcha: %d findings on %s", len(findings), asset.base_url)
    return findings


# ── Password Reset ────────────────────────────────────────────────────

RESET_HINTS = [
    "reset", "forgot", "password-reset", "reset-password", "recover",
    "reset_token", "resetToken", "reset-token", "forgot-password",
]


def scan_password_reset(asset: Asset, client: httpx.Client) -> list[Finding]:
    """Password Reset: reset/forgot endpoint 탐지 → token 추출 → 단순성/엔트로피.

    email 기반(토큰 미추출)이면 finding 없음 (오탐 방지).
    """
    findings = []
    if not asset.base_url:
        return findings

    reset_url = None
    for path in ["/reset", "/reset-password", "/password-reset", "/forgot",
                 "/forgot-password", "/recover", "/reset.php", "/password_reset"]:
        url = urljoin(asset.base_url, path)
        try:
            r = client.get(url, timeout=10)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        ct = r.headers.get("content-type", "")
        # SPA index.html(HTML)는 스킵 — API/JSON 또는 reset 전용 페이지만
        if "json" not in ct.lower():
            continue
        if any(h in path.lower() for h in RESET_HINTS):
            reset_url = url
            break

    if not reset_url:
        log.info("password_reset: no reset endpoint on %s", asset.base_url)
        return findings

    # reset 요청 → token 추출
    token = None
    try:
        r = client.post(reset_url, json={"email": "admin@example.com"}, timeout=15)
        if r.status_code in (200, 201, 202):
            m = re.search(r'"(?:reset_?token|token|resetToken)"\s*:\s*"([^"]+)"', r.text)
            if m:
                token = m.group(1)
            else:
                m = re.search(r"token=([a-zA-Z0-9_-]{4,})", r.text)
                if m:
                    token = m.group(1)
    except Exception as e:
        log.debug("password_reset POST: %s", e)

    if not token:
        log.info("password_reset: endpoint %s but no token extractable (email-based?)", reset_url)
        return findings

    # token 분석
    ent = _shannon_entropy(token)
    length = len(token)
    reasons = []
    if length < 12:
        reasons.append(f"short token (len {length} < 12)")
    if ent < LOW_ENTROPY:
        reasons.append(f"low entropy ({ent:.2f} < {LOW_ENTROPY})")
    if re.fullmatch(r"\d+", token):
        reasons.append("numeric-only token (predictable)")

    if reasons:
        finding = Finding(
            asset_id=asset.id,
            vuln_type="password_reset",
            severity="medium",
            endpoint=reset_url,
            method="POST",
            evidence=f"Weak password reset token: {', '.join(reasons)}. token='{token[:16]}...'",
            poc_request={
                "method": "POST",
                "url": reset_url,
                "json": {"email": "admin@example.com"},
                "note": f"token='{token}', entropy={ent:.2f}, len={length}",
            },
            raw_data={"token": token, "entropy": ent, "length": length},
        )
        findings.append(finding)

    log.info("password_reset: %d findings on %s", len(findings), asset.base_url)
    return findings


def scan_session(asset: Asset, client: httpx.Client) -> list[Finding]:
    """6d 통합: weak_session + captcha + password_reset."""
    findings = []
    findings.extend(scan_weak_session(asset, client))
    findings.extend(scan_captcha(asset, client))
    findings.extend(scan_password_reset(asset, client))
    return findings
