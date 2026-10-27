import logging
import threading
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from api.config import settings
from api.storage import JobStorage


logger = logging.getLogger(__name__)


def _time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def readiness_report(storage: JobStorage, now: datetime | None = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    try:
        snapshot = storage.runtime_health_snapshot()
    except Exception:
        return {"status": "not_ready", "checks": {"database": "unavailable", "worker": "unknown"}}
    grace = timedelta(seconds=settings.worker_heartbeat_timeout_seconds)
    workers = snapshot["workers"]
    progressing = [row for row in workers
               if now - _time(row["heartbeat_at"]) <= grace
               and now <= _time(row["progress_deadline_at"]) + grace
               and row["last_poll_at"] and not row["poll_error"]
               and row["phase"] not in {"stopped", "poll_error"}]
    healthy = [row for row in progressing if row["phase"] != "draining"]
    owned = {row["job_id"] for row in progressing if row["job_id"]}
    stalled_jobs = {row["job_id"] for row in workers if row["job_id"] and row not in progressing}
    active_ids = {job["job_id"] for job in snapshot["active_jobs"]
                  if not (job["status"] == "reconciling"
                          and job["runner_status"] == "precheck_retry_scheduled"
                          and job["next_attempt_at"])}
    # A scheduled precheck is waiting in the queue, not owned by its crashed
    # executor. Its parent deadline still applies during that wait.
    overdue = any(job["deadline_at"] and now > _time(job["deadline_at"]) + grace for job in snapshot["active_jobs"])
    worker_ok = bool(healthy) and not ((stalled_jobs & active_ids) - owned) and not overdue
    queue = snapshot["queue"]
    oldest = queue.pop("oldest_created_at")
    queue["oldest_pending_age_seconds"] = max(0, (now - _time(oldest)).total_seconds()) if oldest else 0
    return {
        "status": "ready" if worker_ok else "not_ready",
        "checks": {"database": "ok", "worker": "ok" if worker_ok else "unavailable"},
        "worker": {
            "healthy_count": len(healthy),
            "phases": sorted({row["phase"] for row in workers if now - _time(row["heartbeat_at"]) <= grace}),
            "latest_heartbeat_age_seconds": min((max(0, (now - _time(row["heartbeat_at"])).total_seconds()) for row in workers), default=None),
            "stalled_active_job_count": len((stalled_jobs & active_ids) - owned),
            "execution_deadline_exceeded": bool(overdue),
        },
        "queue": queue,
    }


class WorkerHeartbeat:
    def __init__(self, storage: JobStorage):
        self.storage = storage
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._shutdown: threading.Event | None = None
        self._state = {"worker_id": str(uuid.uuid4()), "last_poll_at": None, "poll_error": False}
        self.progress("starting", settings.worker_progress_timeout_seconds)

    @property
    def phase(self) -> str:
        with self._lock:
            return self._state["phase"]

    def progress(self, phase: str, budget: float, job_id: str | None = None):
        now = datetime.now(timezone.utc)
        with self._lock:
            self._state.update(
                phase=phase, job_id=job_id, progress_at=now.isoformat(),
                progress_deadline_at=(now + timedelta(seconds=max(0, budget))).isoformat(),
            )
            if phase == "poll_error":
                self._state["poll_error"] = True
        self._wake.set()

    def poll_succeeded(self):
        with self._lock:
            self._state.update(last_poll_at=datetime.now(timezone.utc).isoformat(), poll_error=False)

    def _publish(self):
        with self._lock:
            record = {**self._state, "heartbeat_at": datetime.now(timezone.utc).isoformat()}
        if self._shutdown is not None and self._shutdown.is_set() and record["phase"] != "stopped":
            record["phase"] = "draining"
        try:
            self.storage.record_worker_heartbeat(record)
        except Exception:
            logger.warning("Unable to persist worker heartbeat.", exc_info=True)

    def _run(self):
        while not self._stop.is_set():
            self._publish()
            self._wake.wait(settings.worker_heartbeat_interval_seconds)
            self._wake.clear()
        self._publish()

    def start(self, shutdown: threading.Event):
        self._shutdown = shutdown
        self._thread = threading.Thread(target=self._run, name="worker-heartbeat", daemon=True)
        self._thread.start()

    def stop(self):
        self.progress("stopped", 0)
        self._stop.set()
        self._wake.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
