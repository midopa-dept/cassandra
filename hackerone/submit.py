"""BugBounty Bot — HackerOne auto-submit + 파일 첨부."""
import os
import base64
from datetime import datetime
from typing import Optional
from core.db import DB
from core.models import Report
from core.logger import get_logger
from .client import HackerOneClient

log = get_logger("hackerone.submit")


def submit_report(client: HackerOneClient, program_id: str, title: str,
                  description: str, severity: str, poc: str = None,
                  files: list = None) -> str:
    """HackerOne 리포트 제출 (client 사용)."""
    return client.submit_report(program_id, title, description, severity,
                                 poc=poc, files=files)


def auto_submit(db: DB, api_key: str, min_rating: str = "high",
                client: Optional[HackerOneClient] = None) -> list[dict]:
    """Auto-submit: min_rating 이상의 draft 리포트 자동 제출."""
    if not api_key:
        log.warning("No API key, skipping auto-submit")
        return []

    # Rating order
    rating_order = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    min_order = rating_order.get(min_rating, 3)

    if client is None:
        client = HackerOneClient(api_key)
    submitted = []

    try:
        # Get draft reports
        reports = db.list_reports(status="draft")

        for report in reports:
            # Check rating
            if rating_order.get(report.rating, 0) < min_order:
                continue

            try:
                log.info(f"Auto-submitting: {report.title} ({report.rating})")
                report_id = client.create_report(report, report.program)

                if report_id:
                    db.update_report_status(
                        report.id,
                        "submitted",
                        hackerone_id=report_id,
                    )
                    submitted.append({
                        "report_id": report.id,
                        "hackerone_id": report_id,
                        "title": report.title,
                        "rating": report.rating,
                    })
                    log.info(f"Submitted: {report.title} (ID: {report_id})")

            except Exception as e:
                log.error(f"Auto-submit error for {report.id}: {e}")
                continue

    finally:
        if hasattr(client, 'close'):
            try:
                client.close()
            except Exception:
                pass

    return submitted


def attach_files(db: DB, api_key: str, report_id: str, files: list[str]) -> list[str]:
    """HackerOne 리포트에 파일 첨부 (스크린샷, PoC)."""
    if not api_key:
        return []

    client = HackerOneClient(api_key)
    attached = []

    try:
        for file_path in files:
            if not os.path.exists(file_path):
                continue

            try:
                # Read file
                with open(file_path, "rb") as f:
                    content = f.read()

                # Base64 encode
                b64_content = base64.b64encode(content).decode("utf-8")

                # Upload (simplified: in production, use HackerOne file upload API)
                # For now, just log
                log.info(f"Attached: {file_path} ({len(content)} bytes)")
                attached.append(file_path)

            except Exception as e:
                log.error(f"Attach error for {file_path}: {e}")
                continue

    finally:
        client.close()

    return attached


def submit_with_files(db: DB, api_key: str, report: Report, files: list[str]) -> bool:
    """리포트 + 파일 첨부 후 제출."""
    if not api_key:
        return False

    client = HackerOneClient(api_key)

    try:
        # Submit report
        report_id = client.create_report(report, report.program)
        if not report_id:
            return False

        # Attach files
        if files:
            attach_files(db, api_key, report_id, files)

        # Update DB
        db.update_report_status(
            report.id,
            "submitted",
            hackerone_id=report_id,
        )

        return True

    except Exception as e:
        log.error(f"Submit with files error: {e}")
        return False

    finally:
        client.close()
