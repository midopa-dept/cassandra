"""BugBounty Bot — SQLi 스캐너."""
import re
import httpx
from urllib.parse import urlparse, parse_qs, urlencode
from core.models import Finding
from core.logger import get_logger

log = get_logger("scanner.sqli")

SQLI_P
…(압축: 원래 4250자. 필요하면 다시 읽어라)