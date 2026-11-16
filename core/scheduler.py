"""Cassandra Bot — 스케줄러."""
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from .logger import get_logger

log = get_logger("scheduler")


class Scheduler:
    """APScheduler 기반 작업 스케줄러."""

    def __init__(self):
        self.scheduler = BackgroundScheduler()
        self._jobs: dict[str, str] = {}

    def start(self):
        self.scheduler.start()
        log.info("Scheduler started")

    def shutdown(self):
        self.scheduler.shutdown(wait=False)
        log.info("Scheduler stopped")

    def add_job(self, name: str, func, interval_min: int, *args, **kwargs):
        job_id = f"{name}_{interval_min}"
        self.scheduler.add_job(
            func,
            trigger=IntervalTrigger(minutes=interval_min),
            id=job_id,
            args=args,
            kwargs=kwargs,
            replace_existing=True,
        )
        self._jobs[name] = job_id
        log.info(f"Job '{name}' scheduled every {interval_min}m")

    def remove_job(self, name: str):
        job_id = self._jobs.pop(name, None)
        if job_id:
            self.scheduler.remove_job(job_id)
            log.info(f"Job '{name}' removed")

    def running_jobs(self) -> list[dict]:
        jobs = self.scheduler.get_jobs()
        return [
            {
                "id": j.id,
                "name": j.name,
                "next_run": str(j.next_run_time) if j.next_run_time else None,
            }
            for j in jobs
        ]
