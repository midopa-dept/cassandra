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
    """웹 크롤링: 링크, 폼, 파라미터 자동 발견.

    Args:
        base_url: "http://localhost:3000"
        max_pages: 최대 크롤 페이지 수
        max_depth: 최대 크롤 깊이
        client: httpx.Client (없으면 새로 생성)

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

        while queue and len(endpoints) < max_pages:
            url, depth = queue.pop(0)
            if url in seen_urls or depth > max_depth:
                continue
            seen_urls.add(url)

            try:
                resp = client.get(url)
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
        inputs = re.findall(r'<input[^>]*name=["\']([^"\'#]+)["\']', form)
        if action:
            ep.forms.append({
                "action": action.group(1),
                "method": method.group(1).upper() if method else "GET",
                "fields": inputs,
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
        ]

        for path in api_paths:
            url = base_url.rstrip("/") + path
            try:
                resp = client.get(url, timeout=5)
                if resp.status_code < 400:
                    ep = Endpoint(
                        url=url,
                        method="GET",
                        discovered_by="api_crawl",
                    )
                    # If JSON, try to extract param names
                    if "json" in resp.headers.get("Content-Type", ""):
                        try:
                            data = resp.json()
                            if isinstance(data, dict):
                                ep.params = list(data.keys())[:10]
                        except Exception:
                            pass
                    endpoints.append(ep)
            except Exception:
                pass

        return endpoints

    finally:
        if own_client:
            client.close()
