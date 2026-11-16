"""BugBounty Bot — 기존 자산 재스캔."""
import time
from datetime import datetime, timedelta
from core.db import DB
from core.models import Asset
from core.logger import get_logger

log = get_logger("asset.rescan")


def get_assets_due_for_rescan(db: DB, interval_hours: int = 24) -> list[Asset]:
    """마지막 스캔이 interval_hours 이상 지난 자산."""
    cutoff = datetime.utcnow() - timedelta(hours=interval_hours)
    assets = db.list_assets()

    due = []
    for asset in assets:
        if asset.last_scan is None:
            due.append(asset)
            continue
        try:
            last_scan = datetime.fromisoformat(asset.last_scan)
            if last_scan < cutoff:
                due.append(asset)
        except ValueError:
            due.append(asset)

    log.info(f"Rescan: {len(due)} assets due (interval={interval_hours}h)")
    return due


def mark_scanned(db: DB, asset_id: str):
    """자산의 last_scan 업데이트."""
    asset = db.get_asset(asset_id)
    if asset:
        asset.last_scan = datetime.utcnow().isoformat()
        db.save_asset(asset)
