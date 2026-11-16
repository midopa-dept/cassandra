"""BugBounty Bot — 공통 데이터 모델."""
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional
import uuid


def _now() -> str:
    return datetime.utcnow().isoformat()


def _uuid() -> str:
    return str(uuid.uuid4())


# ── 자산 ──────────────────────────────────────────────────────────────

@dataclass
class Endpoint:
    """스캔 대상 엔드포인트 (URL + 파라미터)."""
    url: str = ""
    method: str = "GET"
    params: list[str] = field(default_factory=list)  # ["id", "q", "search"]
    forms: list[dict] = field(default_factory=list)  # [{"action": "/login", "fields": ["user", "pass"]}]
    discovered_by: str = ""  # crawl, robots, sitemap, js, openapi, manual
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "forms": self.forms,
            "discovered_by": self.discovered_by,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Endpoint":
        return cls(
            url=d.get("url", ""),
            method=d.get("method", "GET"),
            params=d.get("params", []),
            forms=d.get("forms", []),
            discovered_by=d.get("discovered_by", ""),
            created_at=d.get("created_at", _now()),
        )


@dataclass
class Asset:
    """스캔 대상 자산 (도메인/서브도메인/API)."""
    id: str = field(default_factory=_uuid)
    domain: str = ""
    base_url: str = ""  # "http://localhost:3000" or "https://example.com"
    subdomains: list[str] = field(default_factory=list)
    endpoints: list[Endpoint] = field(default_factory=list)
    tech_stack: dict[str, str] = field(default_factory=dict)
    cves: list[str] = field(default_factory=list)
    program: str = ""
    scope: str = "in"  # in | out
    last_scan: Optional[str] = None
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "domain": self.domain,
            "base_url": self.base_url,
            "subdomains": self.subdomains,
            "endpoints": [e.to_dict() for e in self.endpoints],
            "tech_stack": self.tech_stack,
            "cves": self.cves,
            "program": self.program,
            "scope": self.scope,
            "last_scan": self.last_scan,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Asset":
        endpoints = []
        for e in d.get("endpoints", []):
            if isinstance(e, dict):
                endpoints.append(Endpoint.from_dict(e))
            elif isinstance(e, str):
                endpoints.append(Endpoint(url=e))
        return cls(
            id=d.get("id", _uuid()),
            domain=d.get("domain", ""),
            base_url=d.get("base_url", ""),
            subdomains=d.get("subdomains", []),
            endpoints=endpoints,
            tech_stack=d.get("tech_stack", {}),
            cves=d.get("cves", []),
            program=d.get("program", ""),
            scope=d.get("scope", "in"),
            last_scan=d.get("last_scan"),
            created_at=d.get("created_at", _now()),
        )


# ── 발견 (Finding) ────────────────────────────────────────────────────

@dataclass
class Finding:
    """스캔에서 발견된 취약점."""
    id: str = field(default_factory=_uuid)
    asset_id: str = ""
    vuln_type: str = ""  # sqli, xss, idor, ssrf, auth_bypass, race_condition, ...
    severity: str = "unknown"  # low, medium, high, critical, unknown
    endpoint: str = ""
    method: str = "GET"
    evidence: str = ""  # raw response, error message, etc.
    poc_request: dict[str, Any] = field(default_factory=dict)  # {method, url, headers, body}
    raw_data: dict[str, Any] = field(default_factory=dict)
    status: str = "new"  # new, triaging, confirmed, false_positive, reported
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "asset_id": self.asset_id,
            "vuln_type": self.vuln_type,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "method": self.method,
            "evidence": self.evidence,
            "poc_request": self.poc_request,
            "raw_data": self.raw_data,
            "status": self.status,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        return cls(
            id=d.get("id", _uuid()),
            asset_id=d.get("asset_id", ""),
            vuln_type=d.get("vuln_type", ""),
            severity=d.get("severity", "unknown"),
            endpoint=d.get("endpoint", ""),
            method=d.get("method", "GET"),
            evidence=d.get("evidence", ""),
            poc_request=d.get("poc_request", {}),
            raw_data=d.get("raw_data", {}),
            status=d.get("status", "new"),
            created_at=d.get("created_at", _now()),
        )


# ── 리포트 ────────────────────────────────────────────────────────────

@dataclass
class Report:
    """HackerOne 제출용 리포트."""
    id: str = field(default_factory=_uuid)
    finding_id: str = ""
    asset_id: str = ""
    program: str = ""
    title: str = ""
    summary: str = ""
    poc: str = ""  # curl command or step-by-step
    impact: str = ""
    recommendation: str = ""
    rating: str = "medium"  # low, medium, high, critical
    status: str = "draft"  # draft, submitted, triaging, accepted, rejected, resolved, paid
    hackerone_id: Optional[str] = None
    payout: Optional[float] = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "asset_id": self.asset_id,
            "program": self.program,
            "title": self.title,
            "summary": self.summary,
            "poc": self.poc,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "rating": self.rating,
            "status": self.status,
            "hackerone_id": self.hackerone_id,
            "payout": self.payout,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Report":
        return cls(
            id=d.get("id", _uuid()),
            finding_id=d.get("finding_id", ""),
            asset_id=d.get("asset_id", ""),
            program=d.get("program", ""),
            title=d.get("title", ""),
            summary=d.get("summary", ""),
            poc=d.get("poc", ""),
            impact=d.get("impact", ""),
            recommendation=d.get("recommendation", ""),
            rating=d.get("rating", "medium"),
            status=d.get("status", "draft"),
            hackerone_id=d.get("hackerone_id"),
            payout=d.get("payout"),
            created_at=d.get("created_at", _now()),
            updated_at=d.get("updated_at", _now()),
        )


# ── 제출 ──────────────────────────────────────────────────────────────

@dataclass
class Submission:
    """HackerOne 제출 기록."""
    id: str = field(default_factory=_uuid)
    report_id: str = ""
    hackerone_report_id: str = ""
    program: str = ""
    status: str = "submitted"  # submitted, triaging, resolved, paid
    payout: Optional[float] = None
    submitted_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "report_id": self.report_id,
            "hackerone_report_id": self.hackerone_report_id,
            "program": self.program,
            "status": self.status,
            "payout": self.payout,
            "submitted_at": self.submitted_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Submission":
        return cls(
            id=d.get("id", _uuid()),
            report_id=d.get("report_id", ""),
            hackerone_report_id=d.get("hackerone_report_id", ""),
            program=d.get("program", ""),
            status=d.get("status", "submitted"),
            payout=d.get("payout"),
            submitted_at=d.get("submitted_at", _now()),
            updated_at=d.get("updated_at", _now()),
        )
