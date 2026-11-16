"""Cassandra Bot — IDOR (Insecure Direct Object Reference) 스캐너."""
import httpx
from core.models import Asset, Endpoint, Finding
from core.logger import get_logger

log = get_logger("scanner.idor")

# IDOR 테스트용 ID 값들
IDOR_IDS = [1, 2, 3, 999, 10000]


def scan_idor(asset: Asset, endpoint: Endpoint, client: httpx.Client) -> list[Finding]:
    """IDOR 스캔: ID 파라미터를 바꿔가며 접근 제어 확인."""
    findings = []
    if not endpoint.params:
        return findings

    base_url = endpoint.url or asset.base_url

    # Find ID-like parameters (numeric or named id/uid/user_id/etc)
    id_params = []
    for param in endpoint.params:
        if param.lower() in ("id", "uid", "user_id", "account_id", "order_id", "item_id", "product_id"):
            id_params.append(param)

    if not id_params:
        return findings

    for param in id_params:
        # Baseline: original request (complete form: target="1", others=name)
        baseline = _request(client, base_url, endpoint.method, {p: ("1" if p == param else p) for p in endpoint.params})
        if baseline is None or baseline.status_code != 200:
            continue

        # Try different IDs (complete form: target=test_id, others=name)
        for test_id in IDOR_IDS[1:]:
            params = {p: (str(test_id) if p == param else p) for p in endpoint.params}
            resp = _request(client, base_url, endpoint.method, params)
            if resp is None:
                continue

            # If different ID returns 200 with similar content, potential IDOR
            if resp.status_code == 200 and len(resp.text) > 50:
                # Check if content is different (not just "not found")
                if resp.text != baseline.text and "not found" not in resp.text.lower():
                    finding = Finding(
                        asset_id=asset.id,
                        vuln_type="idor",
                        severity="medium",
                        endpoint=base_url,
                        method=endpoint.method,
                        evidence=f"IDOR: param '{param}'={test_id} returned 200 with different content (len={len(resp.text)})",
                        poc_request={
                            "method": endpoint.method,
                            "url": base_url,
                            "params": params,
                        },
                        raw_data={"param": param, "test_id": test_id, "status": resp.status_code},
                    )
                    findings.append(finding)

    log.info("idor: %d findings on %s", len(findings), base_url)
    return findings


def _request(client: httpx.Client, url: str, method: str, params: dict) -> httpx.Response | None:
    try:
        if method.upper() == "GET":
            return client.get(url, params=params, timeout=10)
        elif method.upper() == "POST":
            return client.post(url, data=params, timeout=10)
        return client.get(url, params=params, timeout=10)
    except Exception as e:
        log.debug("request failed: %s %s: %s", method, url, e)
        return None
