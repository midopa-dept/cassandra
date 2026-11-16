"""BugBounty Bot — HackerOne triage 상태 추적."""
import time
from datetime import datetime
from core.db import DB
from core.models import Report
from core.logger import get_logger
from .client import HackerOneClient

log = get_logger("hackerone.track")

# HackerOne report states
STATE_MAP = {
    "triage": "triaging",
    "resolved": "resolved",
    "published": "resolved",
    "paid": "paid",
    "rejected": "rejected",
    "closed": "closed",
}


def get_report_status(client: HackerOneClient, report_id: str) -> dict:
    """HackerOne 리포트 상태 조회."""
    return client.get_report_status(report_id)


def track_reports(db: DB, api_key: str) -> list[dict]:
    """제출된 리포트의 HackerOne 상태 추적."""
    if not api_key:
        log.warning("No API key, skipping triage tracking")
        return []

    client = HackerOneClient(api_key)
    updates = []

    try:
        # Get all submitted reports
        reports = db.list_reports(status="submitted")
        reports += db.list_reports(status="triaging")

        for report in reports:
            if not report.hackerone_id:
                continue

            try:
                status = client.get_report_status(report.hackerone_id)
                if not status:
                    continue

                h1_state = status.get("state", "")
                new_state = STATE_MAP.get(h1_state, h1_state)

                # Update if state changed
                if new_state != report.status:
                    log.info(f"Report {report.id}: {report.status} → {new_state}")
                    db.update_report_status(
                        report.id,
                        new_state,
                        hackerone_id=report.hackerone_id,
                        payout=status.get("bounty"),
                    )
                    updates.append({
                        "report_id": report.id,
                        "old_state": report.status,
                        "new_state": new_state,
                        "bounty": status.get("bounty"),
                    })

                # Update payout if available
                bounty = status.get("bounty")
                if bounty and bounty != report.payout:
                    log.info(f"Report {report.id}: payout updated to ${bounty}")
                    db.update_report_status(
                        report.id,
                        report.status,
                        hackerone_id=report.hackerone_id,
                        payout=bounty,
                    )

            except Exception as e:
                log.error(f"Track error for report {report.id}: {e}")
                continue

    finally:
        client.close()

    return updates


def auto_respond_to_questions(db: DB, api_key: str, llm) -> list[dict]:
    """HackerOne 연구원 질문에 LLM으로 자동 응답."""
    if not api_key:
        return []

    client = HackerOneClient(api_key)
    responses = []

    try:
        # Get reports in triaging state
        reports = db.list_reports(status="triaging")

        for report in reports:
            if not report.hackerone_id:
                continue

            try:
                # Check for new messages/questions
                # (Simplified: in production, this would poll the HackerOne API)
                # For now, just log that we checked
                log.debug(f"Checked for questions on report {report.id}")

            except Exception as e:
                log.error(f"Auto-respond error for report {report.id}: {e}")
                continue

    finally:
        client.close()

    return responses
