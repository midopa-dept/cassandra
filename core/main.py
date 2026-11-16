"""BugBounty Bot — 메인 엔트리포인트 (daemon 모드)."""
import argparse
import sys
import time
import signal
from .config import Config
from .db import DB
from .logger import setup_logger
from .scheduler import Scheduler
from .models import Asset

# Import modules
from scanner.web import scan_web
from scanner.infra import scan_infra
from scanner.api import scan_api
from scanner.logic import scan_logic
from scanner.nuclei import scan_nuclei, is_available as nuclei_available
from triage.llm import LLMClient, judge_finding, assess_severity, generate_report
from triage.dedup import dedup_findings
from asset.ct import discover_subdomains
from asset.dns import discover_assets as dns_discover
from asset.rescan import get_assets_due_for_rescan, mark_scanned
from asset.scope import filter_in_scope


class BugBountyBot:
    """BugBounty Bot 메인 클래스."""

    def __init__(self, config: Config):
        self.config = config
        self.db = DB(config.db_path)
        self.scheduler = Scheduler()
        self.llm = LLMClient(
            provider=config.llm.provider,
            model=config.llm.model,
            api_key=config.llm.api_key,
        )
        self.log = setup_logger("bugbounty")

    def start(self):
        """봇 시작."""
        self.log.info("BugBounty Bot starting")
        self.scheduler.start()

        # Register jobs
        self.scheduler.add_job("ct_poll", self._ct_poll_job, self.config.scheduler.ct_min)
        self.scheduler.add_job("dns_discover", self._dns_discover_job, self.config.scheduler.dns_min)
        self.scheduler.add_job("rescan", self._rescan_job, self.config.scheduler.rescan_min)
        self.scheduler.add_job("triage_check", self._triage_check_job, self.config.scheduler.triage_min)

        self.log.info("BugBounty Bot started")

    def stop(self):
        """봇 종료."""
        self.log.info("BugBounty Bot stopping")
        self.scheduler.shutdown()

    # ── Jobs ──────────────────────────────────────────────────────────

    def _ct_poll_job(self):
        """CT log 폴링: 새 서브도메인 발견."""
        self.log.info("CT poll job")
        for program in self.config.hackerone.programs:
            try:
                assets = discover_subdomains(program, program)
                for asset in assets:
                    self.db.save_asset(asset)
                    self.log.info(f"New asset from CT: {asset.domain}")
            except Exception as e:
                self.log.error(f"CT poll error for {program}: {e}")

    def _dns_discover_job(self):
        """DNS brute-force: 새 자산 발견."""
        self.log.info("DNS discover job")
        for program in self.config.hackerone.programs:
            try:
                assets = dns_discover(program, program)
                for asset in assets:
                    self.db.save_asset(asset)
                    self.log.info(f"New asset from DNS: {asset.domain}")
            except Exception as e:
                self.log.error(f"DNS discover error for {program}: {e}")

    def _rescan_job(self):
        """재스캔: 기존 자산 스캔."""
        self.log.info("Rescan job")
        due_assets = get_assets_due_for_rescan(self.db, interval_hours=24)

        for asset in due_assets:
            try:
                self._scan_asset(asset)
                mark_scanned(self.db, asset.id)
            except Exception as e:
                self.log.error(f"Rescan error for {asset.domain}: {e}")

    def _triage_check_job(self):
        """Triage check: HackerOne 리포트 상태 확인."""
        self.log.info("Triage check job")
        # TODO: Implement HackerOne triage tracking
        pass

    # ── Scan ──────────────────────────────────────────────────────────

    def _scan_asset(self, asset: Asset):
        """자산 스캔: web, infra, api, logic, nuclei."""
        self.log.info(f"Scanning {asset.domain}")

        findings = []

        # Web scanner
        if asset.endpoints:
            findings.extend(scan_web(asset, rate_limit=self.config.scan.rate_limit))

        # Infra scanner
        findings.extend(scan_infra(asset))

        # API scanner
        if asset.endpoints:
            findings.extend(scan_api(asset))

        # Logic scanner
        if asset.endpoints:
            findings.extend(scan_logic(asset))

        # Nuclei (if available)
        if nuclei_available():
            findings.extend(scan_nuclei(asset, templates=self.config.scan.nuclei_templates))

        # Dedup
        findings = dedup_findings(self.db, findings)

        # Save findings
        for finding in findings:
            finding.asset_id = asset.id
            self.db.save_finding(finding)
            self.log.info(f"Finding: {finding.vuln_type} ({finding.severity}) on {asset.domain}")

        # Triage (LLM)
        for finding in findings:
            self._triage_finding(finding, asset)

    def _triage_finding(self, finding, asset: Asset):
        """Triage: LLM 판단 + 리포트 생성."""
        # Judge
        result = judge_finding(self.llm, finding, asset)
        if not result.get("is_real", True):
            self.db.update_finding_status(finding.id, "false_positive")
            return

        # Severity
        severity = assess_severity(self.llm, finding, asset)
        finding.severity = severity
        self.db.save_finding(finding)

        # Report
        report = generate_report(self.llm, finding, asset, severity)
        self.db.save_report(report)
        self.log.info(f"Report: {report.title} ({report.rating})")

        # Auto-submit (if high/critical)
        if self._should_auto_submit(report.rating):
            self._submit_report(report)

    def _should_auto_submit(self, rating: str) -> bool:
        """Auto-submit: high/critical만."""
        threshold = self.config.llm.auto_submit_min
        order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return order.get(rating, 0) >= order.get(threshold, 3)

    def _submit_report(self, report):
        """HackerOne 제출."""
        from hackerone.client import HackerOneClient

        if not self.config.hackerone.api_key:
            self.log.warning("No HackerOne API key, skipping submit")
            return

        try:
            client = HackerOneClient(
                self.config.hackerone.api_key,
                session_id=self.config.hackerone.session_id,
                csrf_token=self.config.hackerone.csrf_token,
            )
            report_id = client.create_report(report, report.program)
            if report_id:
                self.db.update_report_status(report.id, "submitted", hackerone_id=report_id)
                self.log.info(f"Submitted: {report.title} (ID: {report_id})")
            client.close()
        except Exception as e:
            self.log.error(f"Submit error: {e}")


def main():
    parser = argparse.ArgumentParser(description="BugBounty Bot")
    parser.add_argument("--config", default="config.yaml", help="설정 파일 경로")
    parser.add_argument("--db", default=None, help="SQLite 경로")
    parser.add_argument("--once", action="store_true", help="한 번만 실행")
    args = parser.parse_args()

    config = Config.load(args.config)
    if args.db:
        config.db_path = args.db

    bot = BugBountyBot(config)

    if args.once:
        bot.start()
        # Run one scan cycle
        bot._rescan_job()
        bot.stop()
    else:
        bot.start()

        # Handle signals
        def signal_handler(sig, frame):
            bot.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            bot.stop()


if __name__ == "__main__":
    main()
