"""Cassandra Bot — 중복 제거."""
from core.models import Finding
from core.db import DB


def is_duplicate(db: DB, finding: Finding) -> bool:
    """같은 asset + 같은 vuln_type + 같은 endpoint이면 중복."""
    existing = db.list_findings(asset_id=finding.asset_id)
    for f in existing:
        if f.vuln_type == finding.vuln_type and f.endpoint == finding.endpoint:
            return True
    return False


def dedup_findings(db: DB, findings: list[Finding]) -> list[Finding]:
    """중복 제거: 같은 asset + vuln_type + endpoint 중 가장 높은 severity만 남김."""
    seen = {}
    for f in findings:
        key = (f.asset_id, f.vuln_type, f.endpoint)
        if key not in seen:
            seen[key] = f
        else:
            # Keep the one with higher severity
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
            if severity_order.get(f.severity, 0) > severity_order.get(seen[key].severity, 0):
                seen[key] = f
    return list(seen.values())
