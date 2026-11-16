"""BugBounty Bot — 로그인/인증 처리 (DVWA, Juice Shop 등).

로그인 폼 탐지, 자동 로그인, 세션 유지.
"""
import httpx
from urllib.parse import urljoin
from core.models import Asset, Endpoint
from core.logger import get_logger

log = get_logger("scanner.login")

# 알려진 로그인 경로
LOGIN_PATHS = [
    "/login",
    "/logon",
    "/signin",
    "/sign-in",
    "/auth",
    "/authenticate",
    "/user/login",
    "/admin/login",
    "/wp-login.php",
    "/user/login.php",
    "/login.php",
    "/dologin",
    "/do_login",
]

# DVWA 기본 크레덴셜 (예시 — 실제 앱은 config.yaml에서 설정)
DVWA_CREDENTIALS = {
    "user": "admin",
    "pass": "password",
}

# Juice Shop 기본 크레덴셜 (예시 — 실제 앱은 config.yaml에서 설정)
JUICE_SHOP_CREDENTIALS = {
    "username": "admin",
    "password": "admin123",
}


def find_login_form(asset: Asset, client: httpx.Client) -> Endpoint | None:
    """로그인 폼 탐지: 알려진 경로 + HTML form 분석."""
    if not asset.base_url:
        return None

    # 1. 알려진 경로 시도
    for path in LOGIN_PATHS:
        url = urljoin(asset.base_url, path)
        try:
            resp = client.get(url, timeout=10)
            if resp.status_code == 200:
                # HTML form 확인
                if "<form" in resp.text.lower() and ("password" in resp.text.lower() or "pass" in resp.text.lower()):
                    endpoint = Endpoint(
                        url=url,
                        method="POST",
                        params=[],
                        forms=[{"action": path, "fields": ["user", "pass"]}],
                        discovered_by="login-path",
                    )
                    log.info("login form found: %s", url)
                    return endpoint
        except Exception:
            continue

    # 2. asset.endpoints 에서 form 있는 것 찾기
    for ep in asset.endpoints:
        if ep.forms:
            for form in ep.forms:
                if "pass" in str(form.get("fields", [])).lower():
                    log.info("login form in endpoints: %s", ep.url)
                    return ep

    return None


def login(asset: Asset, client: httpx.Client, credentials: dict | None = None) -> bool:
    """로그인: 폼 탐지 + CSRF token + POST + 세션 확인.

    DVWA: login.php POST는 항상 302 (성공→index.php, 실패→login.php).
    'Login' 버튼이 없으면 로그인 처리 자체가 안 되어 200(폼 재렌더) 반환.
    성공/실패는 status code가 아니라 Location 헤더로 판별.
    """
    if not asset.base_url:
        return False

    # 크레덴셜 선택
    if credentials is None:
        if "dvwa" in asset.base_url.lower():
            credentials = DVWA_CREDENTIALS
        elif "juice" in asset.base_url.lower():
            credentials = JUICE_SHOP_CREDENTIALS
        else:
            credentials = DVWA_CREDENTIALS

    # 로그인 폼 탐지
    login_ep = find_login_form(asset, client)
    if login_ep is None:
        log.warning("no login form found for %s", asset.base_url)
        return False

    import re

    def _fetch_token() -> str | None:
        """로그인 폼에서 CSRF 토큰 재추출 (새 세션 대응)."""
        try:
            r = client.get(login_ep.url, timeout=10)
            m = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
            return m.group(1) if m else None
        except Exception:
            return None

    # DVWA 스타일 감지: base_url 문자열 또는 user_token hidden field 존재
    is_dvwa = "dvwa" in asset.base_url.lower()
    tok = _fetch_token()
    if tok:
        is_dvwa = True

    try:
        if is_dvwa:
            # DVWA: 'Login' 버튼 필수 (없으면 로그인 처리 안 됨 → 200)
            data = {
                "username": credentials.get("user", "admin"),
                "password": credentials.get("pass", "password"),
                "Login": "Login",
            }
            if tok:
                data["user_token"] = tok
                log.info("CSRF token: %s", tok)
        else:
            data = {
                "username": credentials.get("username", credentials.get("user", "admin")),
                "password": credentials.get("password", credentials.get("pass", "password")),
            }

        # POST + 재시도: DVWA는 실패 시 200(폼 재렌더) 또는 302→login.php.
        # 성공은 302→index.php. Location 으로 판별, 최대 3회 재시도.
        resp = client.post(login_ep.url, data=data, timeout=15)
        attempts = 0
        while is_dvwa and attempts < 3 and _login_failed(resp):
            attempts += 1
            log.info("login retry %d (status=%d loc=%r)", attempts, resp.status_code, resp.headers.get("location", ""))
            tok = _fetch_token()
            if tok:
                data["user_token"] = tok
            resp = client.post(login_ep.url, data=data, timeout=15)

        # 로그인 성공 확인
        if _login_succeeded(resp):
            if resp.status_code == 302:
                location = resp.headers.get("location", "")
                if location.startswith("/"):
                    location = urljoin(login_ep.url, location)
                if "login" not in location.lower():
                    log.info("login success (redirect): %s", location)

                    # DVWA: setup.php 로 DB reset + 재로그인
                    if is_dvwa:
                        _dvwa_db_reset(client, asset, credentials)
                        return True

                    # 302 후 메인 페이지 GET (follow_redirects=False 대응)
                    try:
                        main_resp = client.get(location, timeout=10)
                        if main_resp.status_code == 200:
                            log.info("main page loaded: %d bytes", len(main_resp.text))
                    except Exception:
                        pass

                    return True

            if "logout" in resp.text.lower() or "dashboard" in resp.text.lower():
                log.info("login success (200): %s", login_ep.url)
                return True

        # DVWA: 로그인 실패 → DB reset 후 재로그인 (치icken-and-egg 해결)
        # admin 비밀번호가 빈 문자열 등으로 나쁜 상태면, setup.php 로 DB reset 후 재시도.
        if is_dvwa and _login_failed(resp):
            log.info("DVWA login failed → DB reset + re-login")
            _dvwa_db_reset(client, asset, credentials)
            # 재로그인
            tok = _fetch_token()
            if tok:
                data["user_token"] = tok
            resp = client.post(login_ep.url, data=data, timeout=15)
            if _login_succeeded(resp):
                log.info("DVWA login success after DB reset")
                return True

        log.info("login attempt: %s → %d loc=%r", login_ep.url, resp.status_code, resp.headers.get("location", ""))
        return False

    except Exception as e:
        log.error("login failed: %s", e)
        return False


def _login_failed(resp: httpx.Response) -> bool:
    """로그인 실패: 200(폼 재렌더) 또는 302→login.php."""
    if resp.status_code == 200:
        return True
    if resp.status_code == 302:
        return "login" in resp.headers.get("location", "").lower()
    return False


def _login_succeeded(resp: httpx.Response) -> bool:
    """로그인 성공: 302→(login 아님) 또는 200+logout/dashboard."""
    if resp.status_code == 302:
        return "login" not in resp.headers.get("location", "").lower()
    if resp.status_code == 200:
        return "logout" in resp.text.lower() or "dashboard" in resp.text.lower()
    return False


def _dvwa_db_reset(client: httpx.Client, asset: Asset, credentials: dict | None = None) -> None:
    """DVWA: setup.php 로 DB reset 후 재로그인 (session_regenerate_id 대응).

    DVWA reset 시 session_regenerate_id() 가 호출되어 기존 PHPSESSID 가 무효화된다.
    따라서 reset 후 login.php 로 2단계 로그인을 다시 수행해야 한다.
    """
    import re
    try:
        setup_url = urljoin(asset.base_url, "/setup.php")
        resp = client.get(setup_url, timeout=10)
        if resp.status_code != 200:
            log.warning("setup.php: %d", resp.status_code)
            return

        # CSRF token 추출
        m = re.search(r"name='user_token'\s+value='([^']+)'", resp.text)
        if not m:
            log.warning("setup.php: no user_token found")
            return

        data = {
            "create_db": "Create / Reset Database",
            "user_token": m.group(1),
        }
        resp = client.post(setup_url, data=data, timeout=30)
        if resp.status_code in (200, 302):
            log.info("DVWA DB reset: %d", resp.status_code)
        else:
            log.warning("DVWA DB reset: %d", resp.status_code)
            return

        # reset 후 재로그인 (session_regenerate_id 대응)
        log.info("DVWA: re-login after DB reset...")
        if credentials is None:
            credentials = DVWA_CREDENTIALS

        login_url = urljoin(asset.base_url, "/login.php")
        resp = client.get(login_url, timeout=10)
        m = re.search(r"name='user_token'\s+value='([^']+)'", resp.text)

        login_data = {
            "username": credentials.get("user", "admin"),
            "password": credentials.get("pass", "password"),
            "Login": "Login",
        }
        if m:
            login_data["user_token"] = m.group(1)

        resp = client.post(login_url, data=login_data, timeout=15)
        # 재시도: 실패(200 또는 302→login) 시 새 토큰으로 재시도
        attempts = 0
        while _login_failed(resp) and attempts < 3:
            attempts += 1
            log.info("DVWA re-login retry %d (status=%d loc=%r)", attempts, resp.status_code, resp.headers.get("location", ""))
            r = client.get(login_url, timeout=10)
            m = re.search(r"name='user_token'\s+value='([^']+)'", r.text)
            if m:
                login_data["user_token"] = m.group(1)
            resp = client.post(login_url, data=login_data, timeout=15)

        if _login_succeeded(resp):
            log.info("DVWA re-login after reset: success (status=%d loc=%r)", resp.status_code, resp.headers.get("location", ""))
        else:
            log.warning("DVWA re-login after reset: failed (status=%d loc=%r)", resp.status_code, resp.headers.get("location", ""))

    except Exception as e:
        log.warning("DVWA DB reset failed: %s", e)


def get_authenticated_client(asset: Asset, credentials: dict | None = None) -> httpx.Client:
    """인증된 httpx.Client 반환 (cookie jar 유지).

    follow_redirects=False 로 로그인 302 의 상대 Location 파싱 버그 회피.
    """
    client = httpx.Client(base_url=asset.base_url, follow_redirects=False)

    if login(asset, client, credentials):
        log.info("authenticated client ready for %s", asset.base_url)
    else:
        log.warning("login failed, using unauthenticated client for %s", asset.base_url)

    return client
