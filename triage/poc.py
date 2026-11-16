"""BugBounty Bot — PoC 스크린샷 (Playwright)."""
import base64
import os
from typing import Optional
from core.models import Finding
from core.logger import get_logger

log = get_logger("triage.poc")


def capture_screenshot(url: str, wait_ms: int = 2000) -> Optional[str]:
    """Playwright: URL 스크린샷 (base64 PNG)."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(wait_ms)

            screenshot = page.screenshot(type="png", full_page=True)
            browser.close()

            return base64.b64encode(screenshot).decode("utf-8")
    except Exception as e:
        log.warning(f"Screenshot failed for {url}: {e}")
        return None


def capture_screenshot_file(url: str, output_path: str, wait_ms: int = 2000) -> Optional[str]:
    """Playwright: URL 스크린샷 (파일 저장)."""
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(url, wait_until="networkidle", timeout=30000)
            page.wait_for_timeout(wait_ms)

            page.screenshot(path=output_path, type="png", full_page=True)
            browser.close()

            return output_path
    except Exception as e:
        log.warning(f"Screenshot failed for {url}: {e}")
        return None


def generate_poc_with_screenshot(finding: Finding, output_dir: str = "poc_screenshots") -> dict:
    """PoC: 스크린샷 + curl 명령."""
    os.makedirs(output_dir, exist_ok=True)

    poc_url = finding.poc_request.get("url", "")
    if not poc_url:
        return {"curl": "", "screenshot": None}

    # Generate curl command
    from triage.llm import generate_poc_curl
    curl_cmd = generate_poc_curl(finding)

    # Capture screenshot
    screenshot_path = os.path.join(output_dir, f"{finding.id}.png")
    screenshot_file = capture_screenshot_file(poc_url, screenshot_path)

    return {
        "curl": curl_cmd,
        "screenshot": screenshot_file,
    }
