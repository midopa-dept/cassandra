"""BugBounty Bot — HackerOne 프로그램 scope 관리."""
import re
from typing import Optional
from core.logger import get_logger

log = get_logger("asset.scope")


def parse_scope(scope_str: str) -> list[dict]:
    """HackerOne scope 문자열 파싱.
    
    Examples:
        "*.example.com" → wildcard
        "example.com" → exact
        "api.example.com" → exact
    """
    scopes = []
    for part in scope_str.split(","):
        part = part.strip()
        if not part:
            continue
        if part.startswith("*."):
            scopes.append({"type": "wildcard", "domain": part[2:]})
        else:
            scopes.append({"type": "exact", "domain": part})
    return scopes


def is_in_scope(domain: str, scopes: list[dict]) -> bool:
    """도메인이 scope 안에 있는지 확인."""
    for scope in scopes:
        if scope["type"] == "wildcard":
            if domain.endswith(f".{scope['domain']}") or domain == scope["domain"]:
                return True
        elif scope["type"] == "exact":
            if domain == scope["domain"]:
                return True
    return False


def filter_in_scope(assets: list, scope_str: str) -> list:
    """scope 안의 자산만 필터링."""
    scopes = parse_scope(scope_str)
    return [a for a in assets if is_in_scope(a.domain, scopes)]
