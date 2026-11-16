"""BugBounty Bot — SQLite 저장소."""
import sqlite3
import json
import os
from typing import Optional
from .models import Asset, Finding, Report, Submission


class DB:
    """SQLite 기반 저장소."""

    def __init__(self, path: str = "bugbounty.db"):
        self.path = path
        self._conn_obj = None
        self._init()

    def _init(self):
        if self.path == ":memory:":
            self._conn_obj = sqlite3.connect(":memory:")
            self._conn_obj.row_factory = sqlite3.Row
            self._create_tables(self._conn_obj)
        else:
            conn = self._conn()
            self._create_tables(conn)
            conn.close()

    def _create_tables(self, conn):
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS assets (
                id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                subdomains TEXT DEFAULT '[]',
                endpoints TEXT DEFAULT '[]',
                tech_stack TEXT DEFAULT '{}',
                cves TEXT DEFAULT '[]',
                program TEXT DEFAULT '',
                scope TEXT DEFAULT 'in',
                last_scan TEXT,
                created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                asset_id TEXT NOT NULL,
                vuln_type TEXT NOT NULL,
                severity TEXT DEFAULT 'unknown',
                endpoint TEXT DEFAULT '',
                method TEXT DEFAULT 'GET',
                evidence TEXT DEFAULT '',
                poc_request TEXT DEFAULT '{}',
                raw_data TEXT DEFAULT '{}',
                status TEXT DEFAULT 'new',
                created_at TEXT,
                FOREIGN KEY (asset_id) REFERENCES assets(id)
            );
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                asset_id TEXT NOT NULL,
                program TEXT DEFAULT '',
                title TEXT DEFAULT '',
                summary TEXT DEFAULT '',
                poc TEXT DEFAULT '',
                impact TEXT DEFAULT '',
                recommendation TEXT DEFAULT '',
                rating TEXT DEFAULT 'medium',
                status TEXT DEFAULT 'draft',
                hackerone_id TEXT,
                payout REAL,
                created_at TEXT,
                updated_at TEXT,
                FOREIGN KEY (finding_id) REFERENCES findings(id)
            );
            CREATE TABLE IF NOT EXISTS submissions (
                id TEXT PRIMARY KEY,
                report_id TEXT NOT NULL,
                hackerone_report_id TEXT DEFAULT '',
                program TEXT DEFAULT '',
                status TEXT DEFAULT 'submitted',
                payout REAL,
                submitted_at TEXT,
                updated_at TEXT,
                FOREIGN KEY (report_id) REFERENCES reports(id)
            );
            CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings(asset_id);
            CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
            CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
            CREATE INDEX IF NOT EXISTS idx_reports_program ON reports(program);
        """)
        conn.commit()

    def _conn(self) -> sqlite3.Connection:
        if self.path == ":memory:":
            return self._conn_obj
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    # ── Assets ────────────────────────────────────────────────────────

    def save_asset(self, asset: Asset):
        conn = self._conn()
        conn.execute("""
            INSERT OR REPLACE INTO assets (id, domain, subdomains, endpoints, tech_stack, cves, program, scope, last_scan, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            asset.id, asset.domain,
            json.dumps(asset.subdomains), json.dumps(asset.endpoints),
            json.dumps(asset.tech_stack), json.dumps(asset.cves),
            asset.program, asset.scope, asset.last_scan, asset.created_at,
        ))
        conn.commit()
        if self.path != ":memory:":
            conn.close()

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if self.path != ":memory:":
            conn.close()
        if not row:
            return None
        return Asset.from_dict({
            "id": row["id"],
            "domain": row["domain"],
            "subdomains": json.loads(row["subdomains"]),
            "endpoints": json.loads(row["endpoints"]),
            "tech_stack": json.loads(row["tech_stack"]),
            "cves": json.loads(row["cves"]),
            "program": row["program"],
            "scope": row["scope"],
            "last_scan": row["last_scan"],
            "created_at": row["created_at"],
        })

    def list_assets(self, program: Optional[str] = None) -> list[Asset]:
        conn = self._conn()
        if program:
            rows = conn.execute("SELECT * FROM assets WHERE program = ?", (program,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM assets").fetchall()
        if self.path != ":memory:":
            conn.close()
        return [Asset.from_dict({
            "id": r["id"],
            "domain": r["domain"],
            "subdomains": json.loads(r["subdomains"]),
            "endpoints": json.loads(r["endpoints"]),
            "tech_stack": json.loads(r["tech_stack"]),
            "cves": json.loads(r["cves"]),
            "program": r["program"],
            "scope": r["scope"],
            "last_scan": r["last_scan"],
            "created_at": r["created_at"],
        }) for r in rows]

    # ── Findings ──────────────────────────────────────────────────────

    def save_finding(self, finding: Finding):
        conn = self._conn()
        conn.execute("""
            INSERT OR REPLACE INTO findings (id, asset_id, vuln_type, severity, endpoint, method, evidence, poc_request, raw_data, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            finding.id, finding.asset_id, finding.vuln_type, finding.severity,
            finding.endpoint, finding.method, finding.evidence,
            json.dumps(finding.poc_request), json.dumps(finding.raw_data),
            finding.status, finding.created_at,
        ))
        conn.commit()
        if self.path != ":memory:":
            conn.close()

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        if self.path != ":memory:":
            conn.close()
        if not row:
            return None
        return Finding.from_dict({
            "id": row["id"],
            "asset_id": row["asset_id"],
            "vuln_type": row["vuln_type"],
            "severity": row["severity"],
            "endpoint": row["endpoint"],
            "method": row["method"],
            "evidence": row["evidence"],
            "poc_request": json.loads(row["poc_request"]),
            "raw_data": json.loads(row["raw_data"]),
            "status": row["status"],
            "created_at": row["created_at"],
        })

    def list_findings(self, status: Optional[str] = None, asset_id: Optional[str] = None) -> list[Finding]:
        conn = self._conn()
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if asset_id:
            query += " AND asset_id = ?"
            params.append(asset_id)
        rows = conn.execute(query, params).fetchall()
        if self.path != ":memory:":
            conn.close()
        return [Finding.from_dict({
            "id": r["id"],
            "asset_id": r["asset_id"],
            "vuln_type": r["vuln_type"],
            "severity": r["severity"],
            "endpoint": r["endpoint"],
            "method": r["method"],
            "evidence": r["evidence"],
            "poc_request": json.loads(r["poc_request"]),
            "raw_data": json.loads(r["raw_data"]),
            "status": r["status"],
            "created_at": r["created_at"],
        }) for r in rows]

    def update_finding_status(self, finding_id: str, status: str):
        conn = self._conn()
        conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
        conn.commit()
        if self.path != ":memory:":
            conn.close()

    # ── Reports ───────────────────────────────────────────────────────

    def save_report(self, report: Report):
        conn = self._conn()
        conn.execute("""
            INSERT OR REPLACE INTO reports (id, finding_id, asset_id, program, title, summary, poc, impact, recommendation, rating, status, hackerone_id, payout, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            report.id, report.finding_id, report.asset_id, report.program,
            report.title, report.summary, report.poc, report.impact,
            report.recommendation, report.rating, report.status,
            report.hackerone_id, report.payout, report.created_at, report.updated_at,
        ))
        conn.commit()
        if self.path != ":memory:":
            conn.close()

    def get_report(self, report_id: str) -> Optional[Report]:
        conn = self._conn()
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
        if self.path != ":memory:":
            conn.close()
        if not row:
            return None
        return Report.from_dict({
            "id": row["id"],
            "finding_id": row["finding_id"],
            "asset_id": row["asset_id"],
            "program": row["program"],
            "title": row["title"],
            "summary": row["summary"],
            "poc": row["poc"],
            "impact": row["impact"],
            "recommendation": row["recommendation"],
            "rating": row["rating"],
            "status": row["status"],
            "hackerone_id": row["hackerone_id"],
            "payout": row["payout"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })

    def list_reports(self, status: Optional[str] = None, program: Optional[str] = None) -> list[Report]:
        conn = self._conn()
        query = "SELECT * FROM reports WHERE 1=1"
        params = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if program:
            query += " AND program = ?"
            params.append(program)
        rows = conn.execute(query, params).fetchall()
        if self.path != ":memory:":
            conn.close()
        return [Report.from_dict({
            "id": r["id"],
            "finding_id": r["finding_id"],
            "asset_id": r["asset_id"],
            "program": r["program"],
            "title": r["title"],
            "summary": r["summary"],
            "poc": r["poc"],
            "impact": r["impact"],
            "recommendation": r["recommendation"],
            "rating": r["rating"],
            "status": r["status"],
            "hackerone_id": r["hackerone_id"],
            "payout": r["payout"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }) for r in rows]

    def update_report_status(self, report_id: str, status: str, hackerone_id: Optional[str] = None, payout: Optional[float] = None):
        conn = self._conn()
        conn.execute("""
            UPDATE reports SET status = ?, hackerone_id = COALESCE(?, hackerone_id), payout = COALESCE(?, payout), updated_at = datetime('now')
            WHERE id = ?
        """, (status, hackerone_id, payout, report_id))
        conn.commit()
        if self.path != ":memory:":
            conn.close()

    # ── Submissions ───────────────────────────────────────────────────

    def save_submission(self, sub: Submission):
        conn = self._conn()
        conn.execute("""
            INSERT OR REPLACE INTO submissions (id, report_id, hackerone_report_id, program, status, payout, submitted_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            sub.id, sub.report_id, sub.hackerone_report_id, sub.program,
            sub.status, sub.payout, sub.submitted_at, sub.updated_at,
        ))
        conn.commit()
        if self.path != ":memory:":
            conn.close()

    def list_submissions(self, status: Optional[str] = None) -> list[Submission]:
        conn = self._conn()
        if status:
            rows = conn.execute("SELECT * FROM submissions WHERE status = ?", (status,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM submissions").fetchall()
        if self.path != ":memory:":
            conn.close()
        return [Submission.from_dict({
            "id": r["id"],
            "report_id": r["report_id"],
            "hackerone_report_id": r["hackerone_report_id"],
            "program": r["program"],
            "status": r["status"],
            "payout": r["payout"],
            "submitted_at": r["submitted_at"],
            "updated_at": r["updated_at"],
        }) for r in rows]

    # ── Stats ─────────────────────────────────────────────────────────

    def stats(self) -> dict:
        conn = self._conn()
        assets = conn.execute("SELECT COUNT(*) as c FROM assets").fetchone()["c"]
        findings = conn.execute("SELECT COUNT(*) as c FROM findings").fetchone()["c"]
        findings_confirmed = conn.execute("SELECT COUNT(*) as c FROM findings WHERE status = 'confirmed'").fetchone()["c"]
        reports = conn.execute("SELECT COUNT(*) as c FROM reports").fetchone()["c"]
        reports_submitted = conn.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'submitted'").fetchone()["c"]
        reports_accepted = conn.execute("SELECT COUNT(*) as c FROM reports WHERE status = 'accepted'").fetchone()["c"]
        total_payout = conn.execute("SELECT COALESCE(SUM(payout), 0) as s FROM reports").fetchone()["s"]
        if self.path != ":memory:":
            conn.close()
        return {
            "assets": assets,
            "findings": findings,
            "findings_confirmed": findings_confirmed,
            "reports": reports,
            "reports_submitted": reports_submitted,
            "reports_accepted": reports_accepted,
            "total_payout": total_payout,
        }
