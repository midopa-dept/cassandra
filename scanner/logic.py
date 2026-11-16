"""BugBounty Bot — 로직 버그 스캐너 (race condition, payment bypass)."""
import httpx
import time
import threading
from typing import Optional
from core.models import Asset, Finding
from core.logger import get_logger

log = get_logger("scanner.logic")


# ── Race Condition ────────────────────────────────────────────────────

def scan_race_condition(base_url: str, endpoint: str, method: str = "POST",
                        body: Optional[dict] = None, headers: Optional[dict] = None,
                        concurrent_requests: int = 10) -> list[Finding]:
    """Race condition: 동시 요청으로 상태 변경 확인."""
    findings = []
    url = endpoint if endpoint.startswith("http") else f"{base_url}{endpoint}"
    default_headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    if headers:
        default_headers.update(headers)

    results = []
    errors = []

    def make_request():
        try:
            if method.upper() == "GET":
                resp = httpx.get(url, headers=default_headers, timeout=10)
            elif method.upper() == "POST":
                resp = httpx.post(url, json=body, headers=default_headers, timeout=10)
            else:
                resp = httpx.request(method.upper(), url, headers=default_headers, timeout=10)
            results.append({
                "status_code": resp.status_code,
                "text": resp.text[:500],
            })
        except Exception as e:
            errors.append(str(e))

    # Send concurrent requests
    threads = []
    for _ in range(concurrent_requests):
        t = threading.Thread(target=make_request)
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Check for inconsistent responses
    if results:
        status_codes = set(r["status_code"] for r in results)
        texts = set(r["text"] for r in results)

        # If different responses, potential race condition
        if len(status_codes) > 1 or len(texts) > 1:
            findings.append(Finding(
                vuln_type="race_condition",
                severity="high",
                endpoint=url,
                method=method,
                evidence=f"Race condition: {len(status_codes)} different status codes, {len(texts)} different responses from {concurrent_requests} concurrent requests",
                poc_request={
                    "method": method,
                    "url": url,
                    "body": body,
                    "headers": default_headers,
                    "concurrent": concurrent_requests,
                },
                raw_data={
                    "status_codes": list(status_codes),
                    "unique_responses": len(texts),
                    "errors": errors,
                },
            ))

    return findings


# ── Payment Bypass ────────────────────────────────────────────────────

def scan_payment_bypass(base_url: str, endpoint: str, method: str = "POST",
                        body: Optional[dict] = None, headers: Optional[dict] = None) -> list[Finding]:
    """Payment bypass: amount=0, negative amount, etc."""
    findings = []
    url = endpoint if endpoint.startswith("http") else f"{base_url}{endpoint}"
    default_headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    if headers:
        default_headers.update(headers)

    if not body:
        return findings

    # Try different amounts
    test_bodies = []
    for key in body:
        if "amount" in key.lower() or "price" in key.lower() or "total" in key.lower():
            # Zero amount
            test_body = dict(body)
            test_body[key] = 0
            test_bodies.append((f"{key}=0", test_body))

            # Negative amount
            test_body = dict(body)
            test_body[key] = -100
            test_bodies.append((f"{key}=-100", test_body))

            # Very small amount
            test_body = dict(body)
            test_body[key] = 0.01
            test_bodies.append((f"{key}=0.01", test_body))

    for desc, test_body in test_bodies:
        try:
            if method.upper() == "POST":
                resp = httpx.post(url, json=test_body, headers=default_headers, timeout=10)
            else:
                resp = httpx.request(method.upper(), url, json=test_body, headers=default_headers, timeout=10)

            # If 200 and success message, potential bypass
            if resp.status_code == 200:
                text_lower = resp.text.lower()
                if any(kw in text_lower for kw in ["success", "completed", "paid", "done"]):
                    findings.append(Finding(
                        vuln_type="payment_bypass",
                        severity="critical",
                        endpoint=url,
                        method=method,
                        evidence=f"Payment bypass: {desc} returned success",
                        poc_request={
                            "method": method,
                            "url": url,
                            "body": test_body,
                            "headers": default_headers,
                        },
                        raw_data={"status_code": resp.status_code, "response": resp.text[:500]},
                    ))
        except Exception:
            continue

    return findings


# ── Workflow Skip ─────────────────────────────────────────────────────

def scan_workflow_skip(base_url: str, endpoints: list[str], method: str = "POST",
                       body: Optional[dict] = None, headers: Optional[dict] = None) -> list[Finding]:
    """Workflow skip: step 1 → step 3 (skip step 2)."""
    findings = []
    default_headers = {"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}
    if headers:
        default_headers.update(headers)

    # Try accessing later steps directly (only if URL has step/phase/stage keywords)
    step_keywords = ["step", "phase", "stage", "wizard", "checkout"]
    for i, endpoint in enumerate(endpoints):
        if i == 0:
            continue  # Skip first step

        url = endpoint if endpoint.startswith("http") else f"{base_url}{endpoint}"
        # Only check if URL looks like a multi-step workflow
        if not any(kw in url.lower() for kw in step_keywords):
            continue

        try:
            if method.upper() == "POST":
                resp = httpx.post(url, json=body, headers=default_headers, timeout=10)
            else:
                resp = httpx.get(url, headers=default_headers, timeout=10)

            # If 200, potential workflow skip
            if resp.status_code == 200:
                findings.append(Finding(
                    vuln_type="workflow_skip",
                    severity="medium",
                    endpoint=url,
                    method=method,
                    evidence=f"Workflow skip: step {i+1} accessible without completing previous steps",
                    poc_request={
                        "method": method,
                        "url": url,
                        "body": body,
                        "headers": default_headers,
                    },
                    raw_data={"status_code": resp.status_code, "step": i + 1},
                ))
        except Exception:
            continue

    return findings


# ── 메인 스캔 함수 ────────────────────────────────────────────────────

def scan_logic(asset: Asset) -> list[Finding]:
    """로직 버그 스캔: race condition, payment bypass, workflow skip."""
    findings = []
    base_url = f"https://{asset.domain}" if not asset.domain.startswith("http") else asset.domain

    for endpoint in asset.endpoints:
        ep_url = endpoint.url if hasattr(endpoint, "url") else str(endpoint)
        # Race condition (POST endpoints)
        if "/api/" in ep_url:
            findings.extend(scan_race_condition(base_url, ep_url, method="POST", concurrent_requests=5))

        # Payment bypass (if endpoint looks like payment)
        if any(kw in ep_url.lower() for kw in ["pay", "payment", "checkout", "order"]):
            findings.extend(scan_payment_bypass(base_url, ep_url, method="POST"))

    # Workflow skip (if multiple endpoints)
    if len(asset.endpoints) >= 2:
        ep_urls = [e.url if hasattr(e, "url") else str(e) for e in asset.endpoints]
        findings.extend(scan_workflow_skip(base_url, ep_urls))

    return findings
