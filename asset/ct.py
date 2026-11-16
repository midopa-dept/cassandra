"""BugBounty Bot — Certificate Transparency (CT) log 폴링."""
import httpx
import json
from typing import Optional
from core.models import Asset
from core.logger import get_logger

log = get_logger("asset.ct")

CRT_SH_URL = "https://crt.sh/?q=%s&output=json"


def query_crt_sh(domain: str, client: Optional[httpx.Client] = None) -> list[str]:
    """crt.sh API: 도메인의 모든 서브도메인 (SSL 인증서)."""
    own_client = client is None
    if own_client:
        client = httpx.Client(timeout=30, follow_redirects=True)

    try:
        resp = client.get(CRT_SH_URL, params={"q": f"*.{domain}", "output": "json"})
        resp.raise_for_status()
        data = resp.json()

        names = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for name in name_value.split("\n"):
                name = name.strip().lstrip("*.")
                if name and name.endswith(domain):
                    names.add(name)
        return sorted(names)
    except Exception as e:
        log.warning(f"crt.sh query failed for {domain}: {e}")
        return []
    finally:
        if own_client:
            client.close()


def discover_subdomains(domain: str, program: str = "") -> list[Asset]:
    """새 서브도메인 발견 → Asset 객체 반환."""
    subdomains = query_crt_sh(domain)
    log.info(f"CT: {domain} → {len(subdomains)} subdomains")

    assets = []
    for sub in subdomains:
        asset = Asset(
            domain=sub,
            subdomains=[sub],
            program=program,
            scope="in",
        )
        assets.append(asset)

    return assets
