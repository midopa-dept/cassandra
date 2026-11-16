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

# DVWA 기본 크레덴셜
DVWA_CREDENTIALS = {
    "user": "admin",
    "pass": "password",
}

# Juice Shop 기본 크레덴셜
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

    DVWA: 로그인 후 setup.php 로 DB reset (session 유지 필요).
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

    try:
        # DVWA 스타일
        if "dvwa" in asset.base_url.lower():
            data = {
                "username": credentials.get("user", "admin"),
                "password": credentials.get("pass", "password"),
                "Login": "Login",
            }
            # CSRF token 추출
            resp = client.get(login_ep.url, timeout=10)
            import re
            m = re.search(r"name='user_token'\s+value='([^']+)'", resp.text)
            if m:
                data["user_token"] = m.group(1)
                log.info("CSRF token: %s", m.group(1))
        else:
            data = {
                "username": credentials.get("username", credentials.get("user", "admin")),
                "password": credentials.get("password", credentials.get("pass", "password")),
            }

        resp = client.post(login_ep.url, data=data, timeout=15)

        # 로그인 성공 확인
        if resp.status_code in (200, 302):
            if resp.status_code == 302:
                location = resp.headers.get("location", "")
                # 상대 경로 절대화
                if location.startswith("/"):
                    location = urljoin(login_ep.url, location)
                if "login" not in location.lower():
                    log.info("login success (redirect): %s", location)

                    # DVWA: setup.php 로 DB reset
                    if "dvwa" in asset.base_url.lower():
                        _dvwa_db_reset(client, asset)

                    return True

            if "logout" in resp.text.lower() or "dashboard" in resp.text.lower():
                log.info("login success (200): %s", login_ep.url)
                return True

        log.info("login attempt: %s → %d", login_ep.url, resp.status_code)
        return resp.status_code == 200

    except Exception as e:
        log.error("login failed: %s", e)
        return False


def _dvwa_db_reset(client: httpx.Client, asset: Asset) -> None:
    """DVWA: setup.php 로 DB reset (session 유지 필요)."""
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
            "Reset": "Reset",
            "user_token": m.group(1),
        }
        resp = client.post(setup_url, data=data, timeout=30)
        if resp.status_code in (200, 302):
            log.info("DVWA DB reset: %d", resp.status_code)
        else:
            log.warning("DVWA DB reset: %d", resp.status_code)
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
