import argparse
import logging
import re
import signal
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from datetime import datetime, timezone
from math import ceil
from typing import Any

from api.config import settings
from api.execution import ExecutionTimeout, exclusive_file_lock
from api.ip_policy import (
    DIRECT_ACCESS_ALLOW_ACTIONS,
    validate_direct_access_target,
)
from api.runner_service import (
    AnsibleRunnerService,
    RunnerResult,
    SnapshotRunnerResult,
    runner_service,
)
from api.schemas import JobStatus
from api.runtime_health import WorkerHeartbeat
from api.storage import JobStorage
from api.time_utils import utc_after_iso, utc_now_iso


logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


MANUAL_INTERVENTION_ERROR_MARKERS = (
    "user-defined applications reached the upper limit",
    "no more user-defined applications can be created",
)


class JobWorker:
    def __init__(
        self,
        storage: JobStorage,
        runner: AnsibleRunnerService,
        poll_interval: float = 0.5,
        retry_waiter: Callable[[float], None] | None = None,
    ) -> None:
        self.storage = storage
        self.runner = runner
        self.poll_interval = poll_interval
        self.retry_waiter = retry_waiter or time.sleep
        self.heartbeat = WorkerHeartbeat(storage)

    def run_once(self) -> bool:
        # One parent execution is serialized so an all-node query never observes
        # the middle of a three-firewall mutation.  A recoverable child failure
        # is retried inside this boundary before another parent can overtake it.
        if self.heartbeat.phase != "waiting_lock":
            self.heartbeat.progress("waiting_lock", max(settings.job_timeout_seconds, settings.snapshot_timeout_seconds))
        try:
            with self._parent_orchestration_lock():
                self.heartbeat.progress("polling", settings.worker_progress_timeout_seconds)
                job = self.storage.claim_next_runnable_job(
                    utc_now_iso(), job_timeout_seconds=settings.job_timeout_seconds,
                )
                self.heartbeat.poll_succeeded()
                if job is None:
                    self.heartbeat.progress("idle", max(settings.worker_progress_timeout_seconds, self.poll_interval))
                    return False
                self._job_progress(job, "preparing", settings.worker_progress_timeout_seconds)
                self._execute_job(job)
                self.heartbeat.progress("idle", max(settings.worker_progress_timeout_seconds, self.poll_interval))
        except ExecutionTimeout:
            return False
        return True

    @contextmanager
    def _parent_orchestration_lock(self):
        lock_path = self.storage.database_path.parent / "firewall_parent.lock"
        with exclusive_file_lock(lock_path, settings.runner_lock_timeout_seconds):
            yield

    @staticmethod
    def _remaining_job_seconds(job: dict[str, Any]) -> float:
        if not job.get("deadline_at"):
            return settings.job_timeout_seconds
        return (datetime.fromisoformat(job["deadline_at"]) - datetime.now(timezone.utc)).total_seconds()

    def _require_job_time(self, job: dict[str, Any]) -> float:
        remaining = self._remaining_job_seconds(job)
        if remaining <= 0:
            raise ExecutionTimeout("Job execution deadline exceeded; firewall changes may be partial. Inspect target results before retrying.")
        return remaining

    def _job_progress(self, job: dict[str, Any], phase: str, budget: float):
        self.heartbeat.progress(phase, min(budget, max(0, self._remaining_job_seconds(job))), str(job["job_id"]))

    def run_forever(self, stop_event: threading.Event) -> None:
        self.heartbeat.start(stop_event)
        try:
            while not stop_event.is_set():
                try:
                    if self.run_once():
                        continue
                except Exception:
                    self.heartbeat.progress("poll_error", settings.worker_progress_timeout_seconds)
                    logger.exception("Worker queue polling failed.")
                stop_event.wait(self.poll_interval)
        finally:
            self.heartbeat.stop()

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
            self._require_job_time(job)
            self.storage.ensure_job_targets(
                job_id,
                target_codes,
                str(job["local_tmp_dir"]),
            )
            if str(job.get("action")) in DIRECT_ACCESS_ALLOW_ACTIONS:
                try:
                    validate_direct_access_target(
                        str(job.get("target_ip", "")),
                        int(job.get("mask", 32)),
                    )
                except (TypeError, ValueError) as exc:
                    error_message = str(exc)
                    finished_at = utc_now_iso()
                    for code in target_codes:
                        self.storage.update_job_target(
                            job_id,
                            code,
                            {
                                "status": JobStatus.failed.value,
                                "runner_status": "policy_rejected",
                                "runner_rc": 2,
                                "error_message": error_message,
                                "finished_at": finished_at,
                            },
                        )
                    self.storage.update_job(
                        job_id,
                        {
                            "status": JobStatus.failed.value,
                            "runner_status": "policy_rejected",
                            "runner_rc": 2,
                            "error_message": error_message,
                            "finished_at": finished_at,
                            "next_attempt_at": None,
                        },
                    )
                    logger.warning("Rejected job %s: %s", job_id, error_message)
                    return
            before_states: dict[str, dict[str, Any]] = {}
            if self._requires_baseline_query(job):
                if int(job.get("precheck_attempt_count") or 0) >= settings.precheck_max_attempts:
                    self._schedule_preflight_retry(job, {"precheck": "Precheck attempt limit reached."})
                    return
                attempt = self.storage.start_job_precheck(job_id)
                if attempt is None:
                    return
                job = {**job, "precheck_attempt_count": attempt}
                self.storage.update_job(
                    job_id,
                    {
                        "status": JobStatus.prechecking.value,
                        "runner_status": "initializing_baseline",
                        "runner_rc": None,
                        "error_message": None,
                        "finished_at": None,
                        "next_attempt_at": None,
                    },
                )
                before_states, preflight_errors = self._preflight(job, target_codes)
                if preflight_errors:
                    self._schedule_preflight_retry(job, preflight_errors)
                    return

            self._require_job_time(job)
            if not self.storage.begin_job_application(job_id):
                return
            desired_state = self._resolve_desired_state(job, before_states)
            job = {**job, "desired_state": desired_state}
            self.storage.update_job(
                job_id,
                {
                    "status": JobStatus.applying.value,
                    "runner_status": "applying",
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

            while True:
                mutation_results = self._execute_targets_parallel(
                    job,
                    target_codes,
                    before_states,
                    desired_state,
                )
                ready = [code for code, ok in mutation_results.items() if ok]
                retryable = [code for code, ok in mutation_results.items() if not ok]
                if retryable:
                    if self._prepare_internal_target_retry(job, ready, retryable):
                        continue
                    return

                self.storage.update_job(
                    job_id,
                    {
                        "status": JobStatus.verifying.value,
                        "runner_status": "verifying",
                        "runner_rc": None,
                        "error_message": None,
                    },
                )
                verification_results = self._verify_targets_parallel(
                    job,
                    target_codes,
                    desired_state,
                )
                verified = [
                    code for code, ok in verification_results.items() if ok
                ]
                failed = [
                    code for code, ok in verification_results.items() if not ok
                ]
                if failed:
                    if self._prepare_internal_target_retry(job, verified, failed):
                        continue
                    return
                break

            self._require_job_time(job)
            self.storage.update_job(
                job_id,
                {
                    "status": JobStatus.successful.value,
                    "runner_status": "successful",
                    "runner_rc": 0,
                    "error_message": None,
                    "finished_at": utc_now_iso(),
                    "next_attempt_at": None,
                },
            )
            logger.info(
                "Finished job %s with status=%s.",
                job_id,
                JobStatus.successful.value,
            )
        except Exception as exc:
            self.storage.update_job(
                job_id,
                {
                    "status": JobStatus.failed.value,
                    "runner_status": "timed_out" if isinstance(exc, ExecutionTimeout) else "failed",
                    "runner_rc": 1,
                    "error_message": str(exc),
                    "finished_at": utc_now_iso(),
                    "next_attempt_at": None,
                },
            )
            logger.exception("Job %s failed with an unexpected error.", job_id)

    def _requires_baseline_query(self, job: dict[str, Any]) -> bool:
        """Only query all firewalls when this IP has never had a desired baseline.

        A resumed job already carries its immutable desired state.  A later job
        can derive its next state from the desired-state ledger.  Re-querying all
        firewalls before either case adds latency and, more importantly, turns a
        retry into an unnecessary second precheck.
        """
        # Full deny has an absolute target and needs no common baseline. Each
        # device's removal workflow still verifies ownership before deleting.
        if str(job["action"]) == "deny" or job.get("desired_state"):
            return False
        return self.storage.get_desired_access_state(str(job["target_ip"])) is None

    def _preflight(
        self,
        job: dict[str, Any],
        target_codes: tuple[str, ...],
    ) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
        job_id = str(job["job_id"])
        states: dict[str, dict[str, Any]] = {}
        errors: dict[str, str] = {}
        worker_count = min(len(target_codes), settings.firewall_parallel_workers)
        self._job_progress(job, "prechecking", settings.snapshot_timeout_seconds * ceil(len(target_codes) / worker_count))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(self._query_target_state, job, code, "precheck"): code
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
                            "error_message": None,
                            "finished_at": None,
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

    def _schedule_preflight_retry(
        self,
        job: dict[str, Any],
        errors: dict[str, str],
    ) -> None:
        self._require_job_time(job)
        exhausted = int(job.get("precheck_attempt_count") or 0) >= settings.precheck_max_attempts
        delay = min(
            settings.firewall_reconcile_retry_seconds * 2 ** max(0, int(job.get("precheck_attempt_count") or 1) - 1),
            60, self._remaining_job_seconds(job),
        )
        self.storage.update_job(
            str(job["job_id"]),
            {
                "status": JobStatus.failed.value if exhausted else JobStatus.reconciling.value,
                "runner_status": "precheck_attempt_limit_reached" if exhausted else "precheck_retry_scheduled",
                "runner_rc": 1,
                "error_message": "Firewall precheck failed: {0}".format(
                    "; ".join(
                        "{0}: {1}".format(code, message)
                        for code, message in sorted(errors.items())
                    )
                ),
                "finished_at": utc_now_iso() if exhausted else None,
                "next_attempt_at": None if exhausted else utc_after_iso(delay),
            },
        )

    def _prepare_internal_target_retry(
        self,
        job: dict[str, Any],
        completed: list[str],
        failed: list[str],
    ) -> bool:
        self._require_job_time(job)
        job_id = str(job["job_id"])
        targets = {
            str(target["firewall_code"]): target
            for target in self.storage.list_job_targets(job_id)
        }
        manual_targets = [
            code
            for code in failed
            if targets.get(code, {}).get("status")
            == JobStatus.manual_intervention_required.value
        ]
        if manual_targets:
            details = "; ".join(
                "{0}: {1}".format(
                    code,
                    targets[code].get("error_message") or "manual repair required",
                )
                for code in manual_targets
            )
            self.storage.update_job(
                job_id,
                {
                    "status": JobStatus.manual_intervention_required.value,
                    "runner_status": "manual_intervention_required",
                    "runner_rc": max(
                        int(targets[code].get("runner_rc") or 1)
                        for code in manual_targets
                    ),
                    "error_message": (
                        "Automatic retries stopped because manual intervention is "
                        "required: {0}"
                    ).format(details),
                    "finished_at": utc_now_iso(),
                    "next_attempt_at": None,
                },
            )
            return False

        exhausted_targets = [
            code
            for code in failed
            if int(targets.get(code, {}).get("attempt_count") or 0)
            >= settings.firewall_child_max_attempts
        ]
        if exhausted_targets:
            self.storage.update_job(
                job_id,
                {
                    "status": JobStatus.failed.value,
                    "runner_status": "attempt_limit_reached",
                    "runner_rc": 2 if completed else 1,
                    "error_message": (
                        "Firewall target attempt limit reached (maximum {0}): {1}. "
                        "Automatic retries stopped; manual repair is required."
                    ).format(
                        settings.firewall_child_max_attempts,
                        ", ".join(exhausted_targets),
                    ),
                    "finished_at": utc_now_iso(),
                    "next_attempt_at": None,
                },
            )
            return False

        if completed:
            runner_status = "partially_successful_retrying"
            runner_rc = 2
            message = "Retrying failed firewall targets inside this parent: {0}".format(
                ", ".join(sorted(failed))
            )
        else:
            runner_status = "retrying"
            runner_rc = 1
            message = "Retrying all failed firewall targets inside this parent."
        self.storage.update_job(
            job_id,
            {
                "status": JobStatus.reconciling.value,
                "runner_status": runner_status,
                "runner_rc": runner_rc,
                "error_message": message,
                "finished_at": None,
                "next_attempt_at": None,
            },
        )
        retry_delay = float(settings.firewall_reconcile_retry_seconds)
        self._job_progress(job, "backoff", retry_delay)
        logger.info(
            "Job %s will retry targets %s after %.1f seconds inside the parent.",
            job_id,
            ",".join(sorted(failed)),
            retry_delay,
        )
        self.retry_waiter(min(retry_delay, self._require_job_time(job)))
        self._require_job_time(job)
        return True

    def _build_desired_state(
        self,
        job: dict[str, Any],
        before_states: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        if str(job["action"]) == "deny":
            return {"ip_present": False, "ports": []}
        stored = self.storage.get_desired_access_state(str(job["target_ip"]))
        if stored is not None:
            base = {
                "ip_present": bool(stored["ip_present"]),
                "ports": sorted({int(port) for port in stored["ports"]}),
            }
        else:
            for state in before_states.values():
                membership = state["address_membership"]
                if (
                    not state["application_targets_valid"]
                    or not state["application_group_complete"]
                    or (
                        not state["ip_present"]
                        and (
                            any(value is not None for value in membership.values())
                            or state["application_names"]
                        )
                    )
                ):
                    raise RuntimeError(
                        "Firewall precheck found inconsistent state and no desired-state baseline exists."
                    )
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
        self._job_progress(job, "applying", settings.runner_timeout_seconds * ceil(len(target_codes) / worker_count))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(
                    self._execute_target,
                    job,
                    code,
                    before_states.get(code),
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
        before_state: dict[str, Any] | None,
        desired_state: dict[str, Any],
    ) -> bool:
        job_id = str(job["job_id"])
        previous = self.storage.get_job_target(job_id, firewall_code) or {}
        if (
            previous.get("status") in {"applied", "verifying", "verified"}
            and previous.get("runner_status") in {"successful", "ok"}
            and previous.get("runner_rc") == 0
        ):
            return True

        last_error: str | None = None
        previous_attempts = int(previous.get("attempt_count") or 0)
        if previous_attempts >= settings.firewall_child_max_attempts:
            self.storage.update_job_target(
                job_id,
                firewall_code,
                {
                    "status": "failed",
                    "runner_status": previous.get("runner_status")
                    or "attempt_limit_reached",
                    "error_message": previous.get("error_message")
                    or "Firewall target attempt limit already reached.",
                    "finished_at": utc_now_iso(),
                },
            )
            return False

        attempt = previous_attempts + 1
        remaining = self._require_job_time(job)
        self.storage.start_job_target_attempt(
            job_id,
            firewall_code,
            "applying" if attempt == 1 else "reconciling",
            attempt,
            utc_now_iso(),
        )
        # Re-run commit/save even on a no-op plan: an interrupted previous run
        # may already have changed configuration without finalizing it.
        result: RunnerResult = self.runner.run_trade_access(
            {**job, "force_finalize": True, "execution_timeout_seconds": remaining}, firewall_code,
        )
        runner_failed = result.rc != 0 or result.status not in ("successful", "ok")
        last_error = result.error_message
        if runner_failed:
            last_error = last_error or "ansible-runner status={0}, rc={1}".format(
                result.status,
                result.rc,
            )
            if self._requires_manual_intervention(last_error):
                self.storage.update_job_target(
                    job_id,
                    firewall_code,
                    {
                        "status": JobStatus.manual_intervention_required.value,
                        "runner_status": "manual_intervention_required",
                        "runner_rc": result.rc,
                        "artifact_dir": result.artifact_dir,
                        "error_message": last_error,
                        "finished_at": utc_now_iso(),
                    },
                )
                return False
            self.storage.update_job_target(
                job_id,
                firewall_code,
                {
                    "status": "failed",
                    "runner_status": result.status,
                    "runner_rc": result.rc,
                    "before_state": before_state,
                    "desired_state": desired_state,
                    "artifact_dir": result.artifact_dir,
                    "error_message": last_error,
                    "finished_at": utc_now_iso(),
                },
            )
            # Configuration presence cannot prove engine commit or save success.
            return False

        self.storage.update_job_target(
            job_id,
            firewall_code,
            {
                "status": "applied",
                "runner_status": result.status,
                "runner_rc": result.rc,
                "before_state": before_state,
                "desired_state": desired_state,
                "artifact_dir": result.artifact_dir,
                "error_message": None,
                "finished_at": None,
            },
        )
        return True

    def _verify_targets_parallel(
        self,
        job: dict[str, Any],
        target_codes: tuple[str, ...],
        desired_state: dict[str, Any],
    ) -> dict[str, bool]:
        outcomes: dict[str, bool] = {}
        worker_count = min(len(target_codes), settings.firewall_parallel_workers)
        self._job_progress(job, "verifying", settings.snapshot_timeout_seconds * ceil(len(target_codes) / worker_count))
        with ThreadPoolExecutor(max_workers=worker_count) as executor:
            futures = {
                executor.submit(
                    self._verify_target,
                    job,
                    code,
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
                            "runner_status": "verification_query_failed",
                            "error_message": "Verification query failed: {0}".format(exc),
                            "finished_at": utc_now_iso(),
                        },
                    )
        return outcomes

    def _verify_target(
        self,
        job: dict[str, Any],
        firewall_code: str,
        desired_state: dict[str, Any],
    ) -> bool:
        job_id = str(job["job_id"])
        previous = self.storage.get_job_target(job_id, firewall_code) or {}
        self.storage.update_job_target(
            job_id,
            firewall_code,
            {
                "status": "verifying",
                "finished_at": None,
            },
        )
        try:
            observed_state, _ = self._query_target_state(job, firewall_code)
        except Exception as exc:
            self.storage.update_job_target(
                job_id,
                firewall_code,
                {
                    "status": "failed",
                    "runner_status": "verification_query_failed",
                    "error_message": "Verification query failed: {0}".format(exc),
                    "finished_at": utc_now_iso(),
                },
            )
            return False

        if self._state_matches(observed_state, desired_state):
            runner_status = str(previous.get("runner_status") or "successful")
            if previous.get("runner_rc") != 0 or runner_status not in ("successful", "ok"):
                self.storage.update_job_target(
                    job_id,
                    firewall_code,
                    {
                        "status": "failed",
                        "observed_state": observed_state,
                        "error_message": previous.get("error_message")
                        or "Mutation, commit and save have not completed successfully.",
                        "finished_at": utc_now_iso(),
                    },
                )
                return False
            self.storage.update_job_target(
                job_id,
                firewall_code,
                {
                    "status": "verified",
                    "runner_status": runner_status,
                    "observed_state": observed_state,
                    "error_message": None,
                    "finished_at": utc_now_iso(),
                },
            )
            return True

        self.storage.update_job_target(
            job_id,
            firewall_code,
            {
                "status": "failed",
                "runner_status": "verification_failed",
                "observed_state": observed_state,
                "error_message": "Observed state does not match desired state.",
                "finished_at": utc_now_iso(),
            },
        )
        return False

    @staticmethod
    def _requires_manual_intervention(error_message: str | None) -> bool:
        normalized = (error_message or "").casefold()
        return any(marker in normalized for marker in MANUAL_INTERVENTION_ERROR_MARKERS)

    def _query_target_state(
        self,
        job: dict[str, Any],
        firewall_code: str,
        audit_phase: str = "verify",
    ) -> tuple[dict[str, Any], SnapshotRunnerResult]:
        snapshot = self.runner.run_firewall_snapshot(
            "state", firewall_code, timeout_seconds=self._require_job_time(job),
            audit_job_id=job.get("job_id"), audit_phase=audit_phase,
        )
        if snapshot.rc != 0 or snapshot.payload is None:
            raise RuntimeError(snapshot.error_message or "Firewall state query failed.")
        payload = snapshot.payload
        try:
            address_state = payload["address_state"]
            vsystems = address_state["vsystems"]
            if not vsystems:
                raise ValueError("No virtual systems returned")
            target_ip = str(job["target_ip"])
            membership = {
                vsystem: address_state["by_vsystem"][vsystem].get(target_ip)
                for vsystem in vsystems
            }
            name_pattern = re.compile(
                re.escape(payload["application_prefix"] + target_ip) + r"(?:_[0-9]+)?$"
            )
            applications = [
                application for application in payload["application_state"]["applications"]
                if name_pattern.fullmatch(application["name"])
            ]
            object_names = {application["name"] for application in applications}
            group_names = {
                name for name in payload["application_group_members"]
                if name_pattern.fullmatch(name)
            }
            expected_pair = {"ip": target_ip, "mask": 32}
            targets_valid = all(
                all(pair == expected_pair for pair in application["ip_addresses"])
                and all(
                    (not rule["ports"] or bool(rule["ip_addresses"]))
                    and all(pair == expected_pair for pair in rule["ip_addresses"])
                    for rule in application["rules"]
                )
                for application in applications
            )
            ports = sorted({
                int(port) for application in applications for port in application["ports"]
            })
            if any(port < 1 or port > 65535 for port in ports):
                raise ValueError("Invalid application ports")
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise RuntimeError("Firewall raw state is incomplete or invalid: {0}".format(exc)) from exc
        return {
            "ip_present": all(mask == 32 for mask in membership.values()),
            "ports": ports,
            "address_membership": membership,
            "application_names": sorted(object_names | group_names),
            "application_group_complete": all(
                application["name"] in group_names
                for application in applications if application["ports"]
            ) and group_names.issubset(object_names),
            "application_targets_valid": targets_valid,
        }, snapshot

    @staticmethod
    def _state_matches(
        observed_state: dict[str, Any],
        desired_state: dict[str, Any],
    ) -> bool:
        membership = observed_state.get("address_membership")
        if not membership or not observed_state.get("application_targets_valid"):
            return False
        if desired_state["ip_present"]:
            if (
                not all(mask == 32 for mask in membership.values())
                or not observed_state["application_group_complete"]
            ):
                return False
        elif any(mask is not None for mask in membership.values()) or observed_state["application_names"]:
            return False
        return sorted({int(port) for port in observed_state.get("ports") or []}) == sorted(
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
