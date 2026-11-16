"""BugBounty Bot — 웹 크롤러 (spider).

링크, 폼, 쿼리 파라미터, JS, OpenAPI 를 자동 발견.
"""
import re
import httpx
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Optional
from core.models import Asset, Endpoint
from core.logger import get_logger

log = get_logger("asset.crawl")

# Common query param names to probe
COMMON_PARAMS = [
    "id", "q", "query", "search", "name", "user", "username",
    "email", "page", "sort", "filter", "type", "cat", "category",
    "key", "token", "session", "lang", "locale", "view", "mode",
    "action", "cmd", "op", "func", "do", "run", "exec",
    "file", "path", "dir", "folder", "template", "theme",
    "url", "redirect", "return", "next", "target", "dest",
    "amount", "price", "qty", "quantity", "count", "limit",
    "offset", "start", "end", "from", "to", "date", "time",
]


def crawl(
    base_url: str,
    max_pages: int = 50,
    max_depth: int = 3,
    client: Optional[httpx.Client] = None,
) -> list[Endpoint]:
    """웹 크롤링: 링크, 폼, 파라미터, robots.txt, JS 라우트 자동 발견.

    Args:
        base_url: "http://localhost:3000"
        max_pages: 최대 크롤 페이지 수
        max_depth: 최대 크롤 깊이
        client: httpx.Client (없으면 새로 생성, authenticated client 가능)

    Returns:
        발견된 Endpoint 목록
    """
    own_client = client is None
    if own_client:
        client = httpx.Client(
            timeout=10,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (BugBountyBot/1.0)"},
        )

    try:
        endpoints: list[Endpoint] = []
        seen_urls: set[str] = set()
        queue: list[tuple[str, int]] = [(base_url, 0)]  # (url, depth)

        # robots.txt에서 경로 발견
        _crawl_robots(base_url, client, queue, seen_urls)

        while queue and len(endpoints) < max_pages:
            url, depth = queue.pop(0)
            if url in seen_urls or depth > max_depth:
                continue
            seen_urls.add(url)

            try:
                resp = client.get(url)
                # follow_redirects=False 인 인증 클라이언트에서 301/302 수동 추적
                hops = 0
                while resp.status_code in (301, 302, 303, 307, 308) and hops < 5:
                    loc = resp.headers.get("location", "")
                    if not loc:
                        break
                    loc = urljoin(url, loc)
                    resp = client.get(loc)
                    hops += 1
            except Exception as e:
                log.debug(f"Crawl error {url}: {e}")
                continue

            if resp.status_code >= 400:
                continue

            content_type = resp.headers.get("Content-Type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                continue

            # Extract links
            links = re.findall(r'href=["\']([^"\'#]+)["\']', resp.text)
            forms = re.findall(r'<form[^>]*>(.*?)</form>', resp.text, re.DOTALL)

            # Create endpoint for this page
            ep = _extract_endpoint(url, resp, forms)
            if ep:
                endpoints.append(ep)

            # Queue new links (same domain only)
            if depth < max_depth:
                parsed_base = urlparse(base_url)
                for link in links:
                    full_url = urljoin(url, link)
                    parsed = urlparse(full_url)
                    if parsed.netloc == parsed_base.netloc and full_url not in seen_urls:
                        queue.append((full_url, depth + 1))

            # JS 번들에서 라우트 발견 (SPA)
            if depth < max_depth:
                js_routes = _extract_js_routes(resp, url, client)
                parsed_base = urlparse(base_url)
                for route in js_routes:
                    full_url = urljoin(url, route)
                    parsed = urlparse(full_url)
                    if parsed.netloc == parsed_base.netloc and full_url not in seen_urls:
                        queue.append((full_url, depth + 1))

            # Extract params from URL
            query = resp.request.url.query if hasattr(resp.request, 'url') else ""
            if query:
                params = _extract_params_from_query(query)
                if params:
                    for ep in endpoints:
                        if ep.url == url:
                            ep.params.extend(params)
                            break

            # Extract params from forms
            for form in forms:
                inputs = re.findall(r'<input[^>]*name=["\']([^"\'#]+)["\']', form)
                if inputs:
                    for ep in endpoints:
                        if ep.url == url:
                            ep.params.extend(inputs)
                            break

        # Probe common params on discovered endpoints
        for ep in endpoints:
            if not ep.params:
                ep.params = _probe_params(client, ep.url)

        return endpoints

    finally:
        if own_client:
            client.close()


def _crawl_robots(base_url: str, client: httpx.Client,
                  queue: list[tuple[str, int]], seen_urls: set[str]):
    """robots.txt에서 Disallow/Allow 경로를 queue에 추가."""
    try:
        r = client.get(base_url.rstrip("/") + "/robots.txt", timeout=5)
        if r.status_code != 200:
            return
        parsed_base = urlparse(base_url)
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/" and not path.startswith("#"):
                    full_url = base_url.rstrip("/") + path
                    if full_url not in seen_urls:
                        queue.append((full_url, 1))
    except Exception:
        pass


def _extract_js_routes(resp: httpx.Response, page_url: str,
                       client: httpx.Client) -> list[str]:
    """JS 번들/인라인 스크립트에서 SPA 라우트 추출."""
    routes = []
    # 1. 인라인 스크립트에서 path/route 패턴
    inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', resp.text, re.DOTALL)
    for script in inline_scripts:
        # React/Vue/Angular route patterns
        for m in re.findall(r'["\'](/(?:lessons|vuln|admin|api|dashboard|settings|profile|users|login|register|checkout|cart|products|orders|search|report|files|upload|download|api/v\d+)[^"\']*)["\']', script):
            if m not in routes:
                routes.append(m)
        # path: "/..." pattern
        for m in re.findall(r'path:\s*["\']([^"\']+)["\']', script):
            if m.startswith("/") and m not in routes:
                routes.append(m)

    # 2. 외부 JS 번들에서 라우트 (최대 3개)
    script_srcs = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', resp.text)
    for src in script_srcs[:3]:
        try:
            js_url = urljoin(page_url, src)
            js_resp = client.get(js_url, timeout=5)
            if js_resp.status_code == 200:
                for m in re.findall(r'["\'](/(?:lessons|vuln|admin|api|dashboard|settings|profile|users|login|register|checkout|cart|products|orders|search|report|files|upload|download|api/v\d+)[^"\']*)["\']', js_resp.text):
                    if m not in routes:
                        routes.append(m)
        except Exception:
            pass

    return routes


def _extract_endpoint(url: str, resp: httpx.Response, forms: list[str]) -> Optional[Endpoint]:
    """URL + response → Endpoint."""
    parsed = urlparse(url)
    query = parsed.query
    params = _extract_params_from_query(query)

    ep = Endpoint(
        url=url,
        method="GET",
        params=params,
        discovered_by="crawl",
    )

    # Extract form info
    for form in forms:
        action = re.search(r'action=["\']([^"\'#]+)["\']', form)
        method = re.search(r'method=["\']([^"\'#]+)["\']', form, re.IGNORECASE)
        # input: name + type
        inputs = re.findall(r'<input[^>]*name=["\']([^"\'#]+)["\'][^>]*type=["\']([^"\'#]+)["\']', form)
        inputs_no_type = re.findall(r'<input[^>]*type=["\']([^"\'#]+)["\'][^>]*name=["\']([^"\'#]+)["\']', form)
        # textarea도 필드로 포함 (DVWA xss_s mtxMessage 등)
        textareas = re.findall(r'<textarea[^>]*name=["\']([^"\'#]+)["\']', form)
        # Merge: (name, type) pairs
        field_list = []
        for name, typ in inputs:
            field_list.append({"name": name, "type": typ})
        for typ, name in inputs_no_type:
            field_list.append({"name": name, "type": typ})
        for name in textareas:
            field_list.append({"name": name, "type": "textarea"})
        if action:
            ep.forms.append({
                "action": action.group(1),
                "method": method.group(1).upper() if method else "GET",
                "fields": field_list,
            })
        elif field_list:
            # action 없는 폼: 같은 페이지에 POST (DVWA 등)
            ep.forms.append({
                "action": "",
                "method": method.group(1).upper() if method else "POST",
                "fields": field_list,
            })

    return ep


def _extract_params_from_query(query: str) -> list[str]:
    """Query string → param names."""
    if not query:
        return []
    params = parse_qs(query)
    return list(params.keys())


def _probe_params(client: httpx.Client, url: str) -> list[str]:
    """Common param names probe: which params does this endpoint accept?"""
    found = []
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    for param in COMMON_PARAMS[:10]:  # Limit to 10 for speed
        test_url = f"{base}?{param}=test"
        try:
            r1 = client.get(base, timeout=5)
            r2 = client.get(test_url, timeout=5)
            # If response differs, param is likely accepted
            if r1.text != r2.text and r1.status_code == r2.status_code:
                found.append(param)
        except Exception:
            pass

    return found


def crawl_api(base_url: str, client: Optional[httpx.Client] = None) -> list[Endpoint]:
    """API endpoint discovery: /api, /v1, /v2, /graphql, /openapi.json."""
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=10, follow_redirects=True)

    try:
        endpoints = []
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/v1", "/v2", "/v3",
            "/graphql",
            "/openapi.json", "/swagger.json", "/swagger.yaml",
            "/docs", "/api-docs",
            # Juice Shop specific
            "/api/Products", "/api/Basket", "/api/Customers",
            "/api/Health", "/api/Settings", "/api/Challenges",
            "/api/Feedback", "/api/Logins", "/api/Users",
        ]

        for path in api_paths:
            url = base_url.rstrip("/") + path
            try:
                resp = client.get(url, timeout=5)
                # 오탐 제거: SPA(Angular 등)는 non-API 경로에도 index.html(200) 반환.
                # 실제 API는 application/json. JSON만 endpoint로.
                if resp.status_code >= 400 or "json" not in resp.headers.get("Content-Type", ""):
                    continue
                ep = Endpoint(
                    url=url,
                    method="GET",
                    discovered_by="api_crawl",
                )
                # JSON 파싱: {"data": [...]} 래퍼 처리 (Juice Shop)
                data = None
                try:
                    data = resp.json()
                    if isinstance(data, dict) and isinstance(data.get("data"), list):
                        data = data["data"]
                except Exception:
                    pass
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    ep.params = list(data[0].keys())[:10]
                elif isinstance(data, dict):
                    ep.params = list(data.keys())[:10]
                endpoints.append(ep)

                # List endpoint → item endpoint (e.g., /api/Products/1)
                if isinstance(data, list) and data and isinstance(data[0], dict):
                    id_field = None
                    for key in ["id", "Id", "ID", "_id"]:
                        if key in data[0]:
                            id_field = key
                            break
                    if id_field:
                        first_id = data[0][id_field]
                        item_url = f"{url}/{first_id}"
                        item_resp = client.get(item_url, timeout=5)
                        if item_resp.status_code < 400 and "json" in item_resp.headers.get("Content-Type", ""):
                            item_ep = Endpoint(
                                url=item_url,
                                method="GET",
                                params=[id_field],
                                discovered_by="api_crawl",
                            )
                            endpoints.append(item_ep)
            except Exception:
                pass

        return endpoints

    finally:
        if own_client:
            client.close()
