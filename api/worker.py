import argparse
import logging
import signal
import threading
from typing import Any

from api.config import settings
from api.runner_service import AnsibleRunnerService, runner_service
from api.schemas import JobStatus
from api.storage import JobStorage
from api.time_utils import utc_now_iso


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class JobWorker:
    def __init__(
        self,
        storage: JobStorage,
        runner: AnsibleRunnerService,
        poll_interval: float = 0.5,
    ) -> None:
        self.storage = storage
        self.runner = runner
        self.poll_interval = poll_interval

    def run_once(self) -> bool:
        job = self.storage.claim_next_pending_job(utc_now_iso())
        if job is None:
            return False

        self._execute_job(job)
        return True

    def run_forever(self, stop_event: threading.Event) -> None:
        while not stop_event.is_set():
            try:
                if self.run_once():
                    continue
            except Exception:
                logger.exception("Worker queue polling failed.")
            stop_event.wait(self.poll_interval)

    def _execute_job(self, job: dict[str, Any]) -> None:
        job_id = str(job["job_id"])
        logger.info(
            "Executing job %s: action=%s target_ip=%s",
            job_id,
            job["action"],
            job["target_ip"],
        )

        try:
            result = self.runner.run_trade_access(job)
            final_status = JobStatus.successful.value
            error_message = result.error_message

            if result.rc != 0 or result.status not in ("successful", "ok"):
                final_status = JobStatus.failed.value
                if not error_message:
                    error_message = (
                        "ansible-runner finished with status={0}, rc={1}".format(
                            result.status,
                            result.rc,
                        )
                    )

            self.storage.update_job(
                job_id,
                {
                    "status": final_status,
                    "runner_status": result.status,
                    "runner_rc": result.rc,
                    "error_message": error_message,
                    "finished_at": utc_now_iso(),
                    "artifact_dir": result.artifact_dir,
                },
            )
            logger.info("Finished job %s with status=%s.", job_id, final_status)
        except Exception as exc:
            self.storage.update_job(
                job_id,
                {
                    "status": JobStatus.failed.value,
                    "runner_status": "failed",
                    "runner_rc": 1,
                    "error_message": str(exc),
                    "finished_at": utc_now_iso(),
                },
            )
            logger.exception("Job %s failed with an unexpected error.", job_id)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the trade-access persistent job worker."
    )
    parser.add_argument("--poll-interval", type=float, default=0.5)
    args = parser.parse_args()

    if args.poll_interval <= 0:
        parser.error("--poll-interval must be greater than zero")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    stop_event = threading.Event()

    def request_stop(signum: int, frame: object) -> None:
        del signum, frame
        stop_event.set()

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    storage = JobStorage(settings.database_path)
    worker = JobWorker(storage, runner_service, args.poll_interval)
    print(
        "Trade access worker started: database={0}, poll_interval={1}s".format(
            settings.database_path,
            args.poll_interval,
        ),
        flush=True,
    )
    worker.run_forever(stop_event)
    print("Trade access worker stopped.", flush=True)


if __name__ == "__main__":
    main()
