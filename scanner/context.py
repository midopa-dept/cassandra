"""Cassandra — Scanner Context (감각기관).

순수 관찰만 한다. 판단하지 않는다.
에이전트(뇌)가 이 구조화 데이터를 보고 전략을 세운다.

관찰 항목:
  - 페이지 목록 (크롤링)
  - 각 페이지: HTML 구조, 폼(필드/타입/action), 링크, 스크립트
  - HTTP 헤더 (security headers, cookies, server)
  - 엔드포인트 (API 경로, 메서드)
  - 에러 메시지 (500, stack trace, debug info)
  - 인증 상태 (login/logout, session)
  - 파일/디렉토리 열거 흔적
"""
import httpx
import re
from urllib.parse import urljoin, urlparse, parse_qs
from typing import Optional
from core.config import Config


class ScannerContext:
    """Target을 관찰하고 구조화된 데이터를 반환한다."""

    def __init__(self, config: Config):
        self.config = config
        self.client = httpx.Client(
            follow_redirects=config.scan.follow_redirects,
            timeout=config.scan.timeout,
            headers={"User-Agent": config.scan.user_agent},
        )
        self.visited: set[str] = set()
        self.pages: list[dict] = []
        self.errors: list[dict] = []
        self.endpoints: list[dict] = []

    def scan(self, url: str, max_pages: Optional[int] = None,
             login: Optional[dict] = None) -> dict:
        """Target URL을 크롤링하고 전체 관찰 결과를 반환.

        login: {"url": "/login.php", "username": "...", "password": "..."}
               → 폼의 hidden 필드(CSRF 토큰 등)를 자동 채워 로그인한 뒤 크롤링
        """
        if login:
            landing = self._do_login(login, url)
            if landing:
                # 로그인 성공 → 대시보드(리다이렉트 목표)도 크롤링 시작점에 추가
                url = landing
        max_pages = max_pages or self.config.scan.max_pages
        base_host = urlparse(url).netloc

        queue = [url]
        while queue and len(self.pages) < max_pages:
            page_url = queue.pop(0)
            if page_url in self.visited:
                continue
            self.visited.add(page_url)

            page_data = self._observe_page(page_url)
            if page_data:
                self.pages.append(page_data)
                # 새 링크 발견 → 큐에 추가
                for link in page_data.get("links", []):
                    full = urljoin(page_url, link)
                    if urlparse(full).netloc == base_host and full not in self.visited:
                        queue.append(full)

        # JS 번들에서 API 엔드포인트 추출 (SPA 대상)
        self._extract_js_endpoints(url)

        return {
            "target": url,
            "pages_scanned": len(self.pages),
            "pages": self.pages,
            "errors": self.errors,
            "endpoints": self.endpoints,
            "summary": self._summarize(),
        }

    def _extract_js_endpoints(self, base_url: str):
        """페이지의 <script src> 번들을 받아 API 경로 추출."""
        base_host = urlparse(base_url).netloc
        seen_scripts = set()
        for page in self.pages:
            for s in page.get("scripts", []):
                if s in seen_scripts:
                    continue
                seen_scripts.add(s)
                full = urljoin(page["url"], s)
                if urlparse(full).netloc != base_host:
                    continue
                try:
                    r = self.client.get(full, timeout=self.config.scan.timeout)
                except Exception:
                    continue
                if r.status_code != 200 or len(r.text) < 500:
                    continue
                eps = self._find_api_in_js(r.text)
                for e in eps:
                    if not any(x["path"] == e for x in self.endpoints):
                        self.endpoints.append({
                            "path": e,
                            "methods": [],
                            "source": "js_bundle",
                            "context": full,
                        })

    def _find_api_in_js(self, js: str) -> list[str]:
        """JS 번들에서 API 경로 추출 (backtick/quote 템플릿 리터럴)."""
        eps = set()
        # backtick template literals: `/rest/...`, `/api/...`
        for m in re.finditer(r'\`([^\`$]{2,80})\`', js):
            p = m.group(1).strip()
            if re.match(r'^/(rest|api|admin|graphql)/', p):
                eps.add(p)
        # quoted strings
        for m in re.finditer(r'["\'](/(?:rest|api|admin|graphql)/[a-zA-Z0-9/_\-]{2,60})["\']', js):
            eps.add(m.group(1))
        return sorted(eps)

    def _do_login(self, login: dict, base_url: str):
        """폼 기반 로그인: hidden 필드(CSRF 토큰 등)를 자동 채운 뒤 POST."""
        login_url = login.get("url", "")
        full_url = login_url if login_url.startswith("http") else urljoin(base_url, login_url)

        # 1) 로그인 폼 GET → hidden 필드 수집
        try:
            r = self.client.get(full_url)
        except Exception as e:
            self.errors.append({"url": full_url, "error": f"login GET failed: {e}"})
            return

        data = {}
        for m in re.finditer(r'<input[^>]*type=["\']hidden["\'][^>]*>', r.text, re.IGNORECASE):
            tag = m.group(0)
            name = re.search(r'name=["\']([^"\']*)["\']', tag)
            value = re.search(r'value=["\']([^"\']*)["\']', tag)
            if name:
                data[name.group(1)] = value.group(1) if value else ""

        # 2) username/password + submit 채워 POST
        # submit 버튼 이름도 자동 수집 (DVWA 등 submit name이 필수인 폼)
        for m in re.finditer(r'<input[^>]*type=["\']submit["\'][^>]*>', r.text, re.IGNORECASE):
            tag = m.group(0)
            name = re.search(r'name=["\']([^"\']*)["\']', tag)
            value = re.search(r'value=["\']([^"\']*)["\']', tag)
            if name:
                data[name.group(1)] = value.group(1) if value else "submit"

        data["username"] = login.get("username", "")
        data["password"] = login.get("password", "")
        if login.get("submit"):
            data[login["submit"]] = login["submit"]

        resp = self.client.post(full_url, data=data)
        self.login_status = resp.status_code
        # 로그인 성공 판단: 200/3xx 후 세션 확보. 최종 URL(대시보드) 반환
        if resp.status_code in (200, 301, 302):
            return str(resp.url)
        return None

    def _observe_page(self, url: str) -> Optional[dict]:
        """한 페이지의 모든 관찰 데이터를 수집."""
        try:
            resp = self.client.get(url)
        except Exception as e:
            self.errors.append({"url": url, "error": str(e)})
            return None

        page = {
            "url": url,
            "status": resp.status_code,
            "headers": self._extract_headers(resp.headers),
            "forms": self._extract_forms(resp.text),
            "links": self._extract_links(resp.text, url),
            "scripts": self._extract_scripts(resp.text),
            "meta": self._extract_meta(resp.text),
            "interesting_patterns": self._find_patterns(resp.text, resp.status_code),
            "size_bytes": len(resp.content),
        }

        # 에러 페이지 감지
        if resp.status_code >= 500:
            self.errors.append({
                "url": url,
                "status": resp.status_code,
                "body_snippet": resp.text[:500],
            })

        # API 엔드포인트 감지
        api_endpoints = self._find_api_endpoints(resp.text, url)
        if api_endpoints:
            self.endpoints.extend(api_endpoints)

        return page

    def _extract_headers(self, headers: dict) -> dict:
        """Security-relevant 헤더만 추출."""
        interesting = {
            "server": headers.get("server", ""),
            "x-powered-by": headers.get("x-powered-by", ""),
            "x-frame-options": headers.get("x-frame-options", ""),
            "content-security-policy": headers.get("content-security-policy", ""),
            "x-content-type-options": headers.get("x-content-type-options", ""),
            "strict-transport-security": headers.get("strict-transport-security", ""),
            "set-cookie": headers.get("set-cookie", ""),
            "cache-control": headers.get("cache-control", ""),
            "access-control-allow-origin": headers.get("access-control-allow-origin", ""),
            "www-authenticate": headers.get("www-authenticate", ""),
        }
        # 빈 값 제거
        return {k: v for k, v in interesting.items() if v}

    def _extract_forms(self, html: str) -> list[dict]:
        """모든 <form>의 필드를 추출."""
        forms = []
        for m in re.finditer(r'<form[^>]*>(.*?)</form>', html, re.DOTALL | re.IGNORECASE):
            form_tag = m.group(0)
            content = m.group(1)
            action = re.search(r'action=["\']([^"\']*)["\']', form_tag)
            method = re.search(r'method=["\']([^"\']*)["\']', form_tag, re.IGNORECASE)

            fields = []
            for fm in re.finditer(r'<(input|textarea|select)[^>]*>', content, re.IGNORECASE):
                tag = fm.group(0)
                name = re.search(r'name=["\']([^"\']*)["\']', tag)
                ftype = re.search(r'type=["\']([^"\']*)["\']', tag)
                placeholder = re.search(r'placeholder=["\']([^"\']*)["\']', tag)
                autocomplete = re.search(r'autocomplete=["\']([^"\']*)["\']', tag)
                required = 'required' in tag
                fields.append({
                    "name": name.group(1) if name else "",
                    "type": ftype.group(1) if ftype else ("textarea" if fm.group(1) == "textarea" else "select" if fm.group(1) == "select" else "text"),
                    "placeholder": placeholder.group(1) if placeholder else "",
                    "autocomplete": autocomplete.group(1) if autocomplete else "",
                    "required": required,
                })

            forms.append({
                "action": action.group(1) if action else "",
                "method": (method.group(1) if method else "GET").upper(),
                "fields": fields,
            })
        return forms

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """페이지 내 링크 추출 (동일 도메인만)."""
        links = []
        for m in re.finditer(r'href=["\']([^"\'#]+)["\']', html, re.IGNORECASE):
            link = m.group(1)
            # 스킵: javascript:, mailto:, tel:, data:
            if link.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            full = urljoin(base_url, link)
            if urlparse(full).netloc == urlparse(base_url).netloc:
                links.append(full)
        return list(set(links))

    def _extract_scripts(self, html: str) -> list[str]:
        """스크립트 src + inline script snippet."""
        scripts = []
        for m in re.finditer(r'<script[^>]*src=["\']([^"\']+)["\']', html, re.IGNORECASE):
            scripts.append(m.group(1))
        # inline scripts (첫 200자만)
        for m in re.finditer(r'<script(?![^>]*src)[^>]*>(.{50,})</script>', html, re.DOTALL | re.IGNORECASE):
            snippet = m.group(1).strip()[:200]
            if snippet and snippet not in scripts:
                scripts.append(f"[inline] {snippet}")
        return scripts

    def _extract_meta(self, html: str) -> dict:
        """meta 태그, title, generator."""
        meta = {}
        title = re.search(r'<title[^>]*>([^<]*)</title>', html, re.IGNORECASE)
        if title:
            meta["title"] = title.group(1).strip()
        gen = re.search(r'<meta[^>]*name=["\']generator["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
        if gen:
            meta["generator"] = gen.group(1)
        csrf = re.search(r'<meta[^>]*name=["\']csrf-token["\'][^>]*content=["\']([^"\']*)["\']', html, re.IGNORECASE)
        if csrf:
            meta["csrf_token_present"] = True
        return meta

    def _find_patterns(self, html: str, status: int) -> list[str]:
        """관심 있는 패턴 (판단 아님, 에이전트가 판단)."""
        patterns = []
        checks = [
            (r'stack ?trace|Traceback \(most recent call last\)', "stack_trace"),
            (r'<div[^>]*class="[^"]*error[^"]*"', "error_div"),
            (r'undefined|null\s*==|typeof\s+', "js_debug"),
            (r'/admin|/wp-admin|/phpmyadmin|/console|/debug', "admin_path"),
            (r'\.git/|\.env|\.bak|~|\.swp', "file_disclosure"),
            (r'X-Debug|X-Powered-By|Server:\s*(Apache|nginx|IIS)', "server_info"),
            (r'api[_-]?key|token|secret|password', "credential_hint"),
            (r'@version|Version:\s*\d', "version_string"),
            (r'eval\(|Function\(|setTimeout\("', "dynamic_js"),
        ]
        for pattern, label in checks:
            if re.search(pattern, html, re.IGNORECASE):
                patterns.append(label)
        if status >= 500:
            patterns.append(f"server_error_{status}")
        return patterns

    def _find_api_endpoints(self, html: str, base_url: str) -> list[dict]:
        """JS/HTML에서 API 엔드포인트 추출."""
        endpoints = []
        seen = set()
        # fetch/axios/XHR 패턴
        for m in re.finditer(r'(?:fetch|axios\.\w+|\.open)\(\s*["\']([^"\']+)["\']', html):
            path = m.group(1)
            if path.startswith(("/", "http")) and path not in seen:
                seen.add(path)
                endpoints.append({"path": path, "source": "js_call"})
        # data-url, data-api 속성
        for m in re.finditer(r'data-(?:url|api|endpoint)=["\']([^"\']+)["\']', html):
            path = m.group(1)
            if path not in seen:
                seen.add(path)
                endpoints.append({"path": path, "source": "data_attr"})
        return endpoints

    def _summarize(self) -> dict:
        """스캔 결과 요약 (에이전트가 빠르게 파악)."""
        all_forms = []
        all_patterns = set()
        for p in self.pages:
            all_forms.extend(p.get("forms", []))
            all_patterns.update(p.get("interesting_patterns", []))

        return {
            "total_pages": len(self.pages),
            "total_forms": len(all_forms),
            "form_fields_count": sum(len(f["fields"]) for f in all_forms),
            "unique_patterns": sorted(all_patterns),
            "error_count": len(self.errors),
            "endpoint_count": len(self.endpoints),
            "notable": [
                p["url"] for p in self.pages
                if p.get("interesting_patterns") or p["status"] >= 400
            ][:10],
        }
