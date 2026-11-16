"""BugBounty Bot — API 엔드포인트 크롤링."""
import re
import httpx
from typing import Optional
from core.models import Asset
from core.logger import get_logger

log = get_logger("asset.api_crawl")


def crawl_robots_txt(base_url: str, client: Optional[httpx.Client] = None) -> list[str]:
    """robots.txt →Disallow/Allow 엔드포인트."""
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=15, follow_redirects=True)

    try:
        resp = client.get(f"{base_url}/robots.txt")
        if resp.status_code != 200:
            return []

        endpoints = []
        for line in resp.text.splitlines():
            line = line.strip()
            if line.startswith("Disallow:") or line.startswith("Allow:"):
                path = line.split(":", 1)[1].strip()
                if path and not path.startswith("#"):
                    endpoints.append(path)
        return endpoints
    except Exception:
        return []
    finally:
        if own_client:
            client.close()


def crawl_sitemap(base_url: str, client: Optional[httpx.Client] = None) -> list[str]:
    """sitemap.xml → URL 목록."""
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=15, follow_redirects=True)

    try:
        resp = client.get(f"{base_url}/sitemap.xml")
        if resp.status_code != 200:
            return []

        urls = re.findall(r"<loc>(.*?)</loc>", resp.text)
        return urls
    except Exception:
        return []
    finally:
        if own_client:
            client.close()


def crawl_js_endpoints(base_url: str, client: Optional[httpx.Client] = None) -> list[str]:
    """JS 파일 분석 → API 엔드포인트."""
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=15, follow_redirects=True)

    try:
        # Get main page
        resp = client.get(base_url)
        if resp.status_code != 200:
            return []

        # Find JS files
        js_files = re.findall(r'src=["\']([^"\']+\.js)["\']', resp.text)

        endpoints = set()
        for js_file in js_files[:10]:  # Limit to 10 JS files
            if js_file.startswith("http"):
                js_url = js_file
            else:
                js_url = f"{base_url}/{js_file.lstrip('/')}"

            try:
                js_resp = client.get(js_url)
                if js_resp.status_code != 200:
                    continue

                # Find API endpoints in JS
                # Pattern 1: /api/v1/..., /api/v2/...
                api_patterns = re.findall(r'["\'](/api/[^"\'\s]+)["\']', js_resp.text)
                endpoints.update(api_patterns)

                # Pattern 2: fetch/axios calls
                fetch_patterns = re.findall(r'(?:fetch|axios\.\w+)\(["\']([^"\'\s]+)["\']', js_resp.text)
                for pattern in fetch_patterns:
                    if pattern.startswith("/"):
                        endpoints.add(pattern)

            except Exception:
                continue

        return list(endpoints)
    except Exception:
        return []
    finally:
        if own_client:
            client.close()


def crawl_openapi(base_url: str, client: Optional[httpx.Client] = None) -> list[str]:
    """OpenAPI/Swagger docs → 엔드포인트."""
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=15, follow_redirects=True)

    try:
        # Try common OpenAPI paths
        for path in ["/openapi.json", "/swagger.json", "/api/docs", "/api/openapi.json"]:
            resp = client.get(f"{base_url}{path}")
            if resp.status_code == 200:
                try:
                    data = resp.json()
                    paths = data.get("paths", {})
                    return list(paths.keys())
                except Exception:
                    continue
        return []
    except Exception:
        return []
    finally:
        if own_client:
            client.close()


def discover_endpoints(base_url: str) -> list[str]:
    """모든 소스에서 엔드포인트 수집."""
    endpoints = set()

    with httpx.Client(timeout=15, follow_redirects=True) as client:
        endpoints.update(crawl_robots_txt(base_url, client))
        endpoints.update(crawl_sitemap(base_url, client))
        endpoints.update(crawl_js_endpoints(base_url, client))
        endpoints.update(crawl_openapi(base_url, client))

    log.info(f"API crawl: {base_url} → {len(endpoints)} endpoints")
    return sorted(endpoints)
