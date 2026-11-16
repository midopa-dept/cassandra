"""BugBounty Bot — 웹 앱 스캐너 (SQLi, XSS, IDOR, SSRF, Auth Bypass).

base_url + endpoint + param 을 자동 탐지해서 payload 주입.
"""
import re
import time
import httpx
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Optional
from core.models import Asset, Endpoint, Finding
from core.logger import get_logger

log = get_logger("scanner.web")

# ── SQLi ──────────────────────────────────────────────────────────────

SQLI_P
…(압축: 원래 14024자. 필요하면 다시 읽어라)