import argparse
import fcntl
import logging
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from typing import Any

from api.config import settings
from api.runner_service import AnsibleRunnerService, RunnerResult, SnapshotRunnerResult, runner_service
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
        # Acquire the orchestration lock before claiming so multiple worker
        # processes cannot reverse FIFO order while waiting for the same lock.
        # Parent jobs are serialized; only one parent's firewall children run
        # in parallel at a time.
        with self._parent_orchestration_lock():
            job = self.storage.claim_next_runnable_job(utc_now_iso())
            if job is None:
                return False
            self._execute_job(job)
        return True

    @contextmanager
    def _parent_orchestration_lock(self):
        lock_path = self.storage.database_path.parent / "firewall_parent.lock"
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        with lock_path.open("a", encoding="utf-8") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

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
        target_codes = tuple(job.get("firewall_targets") or settings.firewall_target_codes)
        logger.info(
            "Executing job %s: action=%s target_ip=%s firewalls=%s",
            job_id,
            job["action"],
            job["target_ip"],
            ",".join(target_codes),
        )

        try:
            self.storage.ensure_job_targets(
                job_id,
                target_codes,
                str(job["local_tmp_dir"]),
            )
            self.storage.update_job(job_id, {"status": JobStatus.prechecking.value})
            before_states, preflight_errors = self._preflight(job, target_codes)
            if preflight_errors:
                self._finish_preflight_failure(job, preflight_errors)
                return

            desired_state = self._resolve_desired_state(job, before_states)
            self.storage.update_job(
                job_id,
                {
                    "status": JobStatus.applying.value,
                    "desired_state": desired_state,
                    "state_version": desired_state["version"],
                },
            )
            for code in target_codes:
                self.storage.update_job_target(
                    job_id,
                    code,
                    {"desired_state": desired_state},
                )

            target_results = self._execute_targets_parallel(
                job,
                target_codes,
                before_states,
                desired_state,
            )
            verified = [code for code, ok in target_results.items() if ok]
            failed = [code for code, ok in target_results.items() if not ok]
            if not failed:
                final_status = JobStatus.successful.value
                runner_status = "successful"
                runner_rc = 0
                error_message = None
            elif verified:
                final_status = JobStatus.manual_intervention_required.value
                runner_status = "partially_successful"
                runner_rc = 2
                error_message = "Firewall targets still differ from desired state: {0}".format(
                    ", ".join(failed)
                )
            else:
                final_status = JobStatus.failed.value
                runner_status = "failed"
                runner_rc = 1
                error_message = "No firewall target reached the desired state."

            self.storage.update_job(
                job_id,
                {
                    "status": final_status,
                    "runner_status": runner_status,
                    "runner_rc": runner_rc,
                    "error_message": error_message,
                    "finished_at": utc_now_iso(),
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

    def _preflight(
        self,
        job: dict[str, Any],
        target_codes: tuple[str, ...],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        job_id = str(job["job_id"])
        states: dict[str, dict[str, Any]] = {}
        errors: dict[str, str] = {}
        worker_count = min(len(target_codes), settings.firewall_parallel_workers)
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(self._query_target_state, job, code): code
                for code in target_codes
            }
            for future in as_completed(futures):
                code = futures[future]
                try:
                    state, snapshot = future.result()
                    states[code] = state
                    self.storage.update_job_target(
                        job_id,
                        code,
                        {
                            "status": "prechecked",
                            "before_state": state,
                            "artifact_dir": snapshot.artifact_dir,
                        },
                    )
                except Exception as exc:
                    errors[code] = str(exc)
                    self.storage.update_job_target(
                        job_id,
                        code,
                        {
                            "status": "precheck_failed",
                            "error_message": str(exc),
                            "finished_at": utc_now_iso(),
                        },
                    )
        return states, errors

    def _finish_preflight_failure(
        self,
        job: dict[str, Any],
        errors: dict[str, str],
    ) -> None:
        self.storage.update_job(
            str(job["job_id"]),
            {
                "status": JobStatus.failed.value,
                "runner_status": "precheck_failed",
                "runner_rc": 1,
                "error_message": "Firewall precheck failed: {0}".format(
                    "; ".join(
                        "{0}: {1}".format(code, message)
                        for code, message in sorted(errors.items())
                    )
                ),
                "finished_at": utc_now_iso(),
            },
        )

    def _build_desired_state(
        self,
        job: dict[str, Any],
        before_states: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        stored = self.storage.get_desired_access_state(str(job["target_ip"]))
        if stored is not None:
            base = {
                "ip_present": bool(stored["ip_present"]),
                "ports": sorted({int(port) for port in stored["ports"]}),
            }
        else:
            normalized = {
                (bool(state["ip_present"]), tuple(state["ports"]))
                for state in before_states.values()
            }
            if len(normalized) != 1:
                raise RuntimeError(
                    "Firewall precheck found inconsistent state and no desired-state baseline exists."
                )
            ip_present, ports = next(iter(normalized))
            base = {"ip_present": ip_present, "ports": list(ports)}

        action = str(job["action"])
        requested_ports = {int(port) for port in job.get("ports") or []}
        current_ports = {int(port) for port in base["ports"]}
        if action == "allow":
            return {"ip_present": True, "ports": sorted(current_ports | requested_ports)}
        if action == "allow_ip":
            return {"ip_present": True, "ports": sorted(current_ports)}
        if action == "allow_ports":
            if not base["ip_present"]:
                raise RuntimeError("allow_ports requires the target IP to be allowed first.")
            return {"ip_present": True, "ports": sorted(current_ports | requested_ports)}
        if action == "deny_ports":
            if not base["ip_present"]:
                raise RuntimeError("deny_ports requires the target IP to be present.")
            return {"ip_present": True, "ports": sorted(current_ports - requested_ports)}
        if action == "deny_ip":
            if current_ports:
                raise RuntimeError("deny_ip requires all application ports to be removed first.")
            return {"ip_present": False, "ports": []}
        if action == "deny":
            return {"ip_present": False, "ports": []}
        raise RuntimeError("Unsupported firewall action: {0}".format(action))

    def _resolve_desired_state(
        self,
        job: dict[str, Any],
        before_states: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        persisted = job.get("desired_state")
        if persisted:
            return {
                "ip_present": bool(persisted["ip_present"]),
                "ports": sorted({int(port) for port in persisted.get("ports") or []}),
                "version": int(persisted.get("version") or job["state_version"]),
            }

        ledger_state = self.storage.get_desired_access_state(str(job["target_ip"]))
        # Handles a crash after the ledger transaction committed but before the
        # parent job row was updated with the same version.
        if ledger_state is not None and ledger_state["source_job_id"] == job["job_id"]:
            return {
                "ip_present": bool(ledger_state["ip_present"]),
                "ports": sorted({int(port) for port in ledger_state["ports"]}),
                "version": int(ledger_state["version"]),
            }

        requested = self._build_desired_state(job, before_states)
        saved = self.storage.save_desired_access_state(
            target_ip=str(job["target_ip"]),
            ip_present=bool(requested["ip_present"]),
            ports=list(requested["ports"]),
            source_job_id=str(job["job_id"]),
            updated_at=utc_now_iso(),
        )
        return {
            "ip_present": saved["ip_present"],
            "ports": saved["ports"],
            "version": saved["version"],
        }

    def _execute_targets_parallel(
        self,
        job: dict[str, Any],
        target_codes: tuple[str, ...],
        before_states: dict[str, dict[str, Any]],
        desired_state: dict[str, Any],
    ) -> dict[str, bool]:
        outcomes: dict[str, bool] = {}
        worker_count = min(len(target_codes), settings.firewall_parallel_workers)
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(
                    self._execute_target,
                    job,
                    code,
                    before_states[code],
                    desired_state,
                ): code
                for code in target_codes
            }
            for future in as_completed(futures):
                code = futures[future]
                try:
                    outcomes[code] = bool(future.result())
                except Exception as exc:
                    outcomes[code] = False
                    self.storage.update_job_target(
                        str(job["job_id"]),
                        code,
                        {
                            "status": "failed",
                            "error_message": str(exc),
                            "finished_at": utc_now_iso(),
                        },
                    )
        return outcomes

    def _execute_target(
        self,
        job: dict[str, Any],
        firewall_code: str,
        before_state: dict[str, Any],
        desired_state: dict[str, Any],
    ) -> bool:
        job_id = str(job["job_id"])
        if self._state_matches(before_state, desired_state):
            self.storage.update_job_target(
                job_id,
                firewall_code,
                {
                    "status": "verified",
                    "runner_status": "already_converged",
                    "runner_rc": 0,
                    "before_state": before_state,
                    "desired_state": desired_state,
                    "observed_state": before_state,
                    "error_message": None,
                    "finished_at": utc_now_iso(),
                },
            )
            return True

        last_error: str | None = None
        previous = self.storage.get_job_target(job_id, firewall_code) or {}
        previous_attempts = int(previous.get("attempt_count") or 0)
        for attempt_offset in range(1, settings.firewall_child_max_attempts + 1):
            attempt = previous_attempts + attempt_offset
            self.storage.update_job_target(
                job_id,
                firewall_code,
                {
                    "status": "applying" if attempt == 1 else "reconciling",
                    "attempt_count": attempt,
                    "started_at": utc_now_iso(),
                    "error_message": None,
                },
            )
            result: RunnerResult = self.runner.run_trade_access(job, firewall_code)
            last_error = result.error_message
            if result.rc != 0 or result.status not in ("successful", "ok"):
                last_error = last_error or "ansible-runner status={0}, rc={1}".format(
                    result.status,
                    result.rc,
                )
            self.storage.update_job_target(
                job_id,
                firewall_code,
                {
                    "status": "verifying",
                    "runner_status": result.status,
                    "runner_rc": result.rc,
                    "artifact_dir": result.artifact_dir,
                    "error_message": last_error,
                },
            )
            try:
                observed_state, _ = self._query_target_state(job, firewall_code)
            except Exception as exc:
                last_error = "Verification query failed: {0}".format(exc)
                observed_state = None

            if observed_state is not None and self._state_matches(
                observed_state,
                desired_state,
            ):
                self.storage.update_job_target(
                    job_id,
                    firewall_code,
                    {
                        "status": "verified",
                        "before_state": before_state,
                        "desired_state": desired_state,
                        "observed_state": observed_state,
                        "artifact_dir": result.artifact_dir,
                        "error_message": None,
                        "finished_at": utc_now_iso(),
                    },
                )
                return True

            if observed_state is not None:
                last_error = "Observed state does not match desired state."
            self.storage.update_job_target(
                job_id,
                firewall_code,
                {
                    "status": "reconciling",
                    "observed_state": observed_state,
                    "error_message": last_error,
                    # Keep mutation events available through the job-events API;
                    # verification details are already persisted as state/error.
                    "artifact_dir": result.artifact_dir,
                },
            )

        self.storage.update_job_target(
            job_id,
            firewall_code,
            {
                "status": "failed",
                "error_message": last_error or "Target did not reach desired state.",
                "finished_at": utc_now_iso(),
            },
        )
        return False

    def _query_target_state(
        self,
        job: dict[str, Any],
        firewall_code: str,
    ) -> tuple[dict[str, Any], SnapshotRunnerResult]:
        snapshot = self.runner.run_firewall_snapshot("state", firewall_code)
        if snapshot.rc != 0 or snapshot.payload is None:
            raise RuntimeError(snapshot.error_message or "Firewall state query failed.")
        target_ip = str(job["target_ip"])
        ip_present = any(
            str(item.get("ip")) == target_ip
            for item in snapshot.payload.get("ip_items", [])
        )
        ports = sorted(
            {
                int(item["port"])
                for item in snapshot.payload.get("port_items", [])
                if str(item.get("ip")) == target_ip
            }
        )
        return {"ip_present": ip_present, "ports": ports}, snapshot

    @staticmethod
    def _state_matches(
        observed_state: dict[str, Any],
        desired_state: dict[str, Any],
    ) -> bool:
        return bool(observed_state.get("ip_present")) == bool(
            desired_state.get("ip_present")
        ) and sorted({int(port) for port in observed_state.get("ports") or []}) == sorted(
            {int(port) for port in desired_state.get("ports") or []}
        )


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

    # worker 和 API 共用同一 SQLite 库，任务状态通过数据库交接。
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
