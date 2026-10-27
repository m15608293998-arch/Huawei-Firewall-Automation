import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path

from api.config import settings
from api.runner_service import RunnerResult, SnapshotRunnerResult
from api.storage import JobStorage
from api.worker import JobWorker


class FakeRunner:
    def __init__(
        self,
        states=None,
        failed_codes=None,
        no_op_codes=None,
        snapshot_failed_codes=None,
        mutation_barrier=None,
        verification_started=None,
        verification_release=None,
        failure_messages=None,
        failed_after_apply_codes=None,
        failure_counts=None,
    ):
        self.states = {
            code: {
                "ip_present": bool(state["ip_present"]),
                "ports": sorted(state["ports"]),
            }
            for code, state in (states or {}).items()
        }
        self.failed_codes = set(failed_codes or [])
        self.no_op_codes = set(no_op_codes or [])
        self.snapshot_failed_codes = set(snapshot_failed_codes or [])
        self.mutation_barrier = mutation_barrier
        self.verification_started = verification_started
        self.verification_release = verification_release
        self.failure_messages = dict(failure_messages or {})
        self.failed_after_apply_codes = set(failed_after_apply_codes or [])
        self.remaining_failures = {
            str(code): int(count)
            for code, count in (failure_counts or {}).items()
        }
        self.jobs = []
        self.snapshot_calls = []
        self.active_mutations = 0
        self.max_active_mutations = 0
        self._lock = threading.Lock()

    def run_trade_access(self, job, firewall_code=None):
        code = str(firewall_code)
        with self._lock:
            self.jobs.append((job, code))
            self.active_mutations += 1
            self.max_active_mutations = max(
                self.max_active_mutations,
                self.active_mutations,
            )

        try:
            if self.mutation_barrier is not None:
                self.mutation_barrier.wait(timeout=2)
            with self._lock:
                remaining_failures = self.remaining_failures.get(code, 0)
                if remaining_failures > 0:
                    self.remaining_failures[code] = remaining_failures - 1
                should_fail = (
                    code in self.failed_codes
                    or code in self.failed_after_apply_codes
                    or remaining_failures > 0
                )
            if should_fail and code not in self.failed_after_apply_codes:
                return RunnerResult(
                    status="failed",
                    rc=2,
                    artifact_dir="/tmp/artifacts/{0}/{1}".format(job["job_id"], code),
                    error_message=self.failure_messages.get(code),
                )

            if code in self.no_op_codes:
                return RunnerResult(
                    status="successful",
                    rc=0,
                    artifact_dir="/tmp/artifacts/{0}/{1}".format(job["job_id"], code),
                )

            with self._lock:
                state = self.states.setdefault(
                    code,
                    {"ip_present": False, "ports": []},
                )
                ports = set(state["ports"])
                requested = {int(port) for port in job.get("ports") or []}
                action = job["action"]
                if action == "allow":
                    state["ip_present"] = True
                    ports.update(requested)
                elif action == "allow_ip":
                    state["ip_present"] = True
                elif action == "allow_ports":
                    ports.update(requested)
                elif action == "deny_ports":
                    ports.difference_update(requested)
                elif action in {"deny_ip", "deny"}:
                    state["ip_present"] = False
                    if action == "deny":
                        ports.clear()
                if action in {"allow", "allow_ports", "deny_ports"} and job.get("desired_state"):
                    ports = set(job["desired_state"]["ports"])
                state["ports"] = sorted(ports)

            if should_fail and code in self.failed_after_apply_codes:
                return RunnerResult(
                    status="failed",
                    rc=2,
                    artifact_dir="/tmp/artifacts/{0}/{1}".format(job["job_id"], code),
                    error_message=self.failure_messages.get(code),
                )

            return RunnerResult(
                status="successful",
                rc=0,
                artifact_dir="/tmp/artifacts/{0}/{1}".format(job["job_id"], code),
            )
        finally:
            with self._lock:
                self.active_mutations -= 1

    def run_firewall_snapshot(self, snapshot_mode="snapshot", firewall_code=None, timeout_seconds=None):
        code = str(firewall_code)
        with self._lock:
            self.snapshot_calls.append((snapshot_mode, code))
            snapshot_call_count = len(self.snapshot_calls)
            if code in self.snapshot_failed_codes:
                return SnapshotRunnerResult(
                    status="failed",
                    rc=1,
                    artifact_dir="/tmp/snapshots/{0}".format(code),
                    error_message="snapshot failed",
                )
            state = dict(
                self.states.setdefault(
                    code,
                    {"ip_present": False, "ports": []},
                )
            )

        if snapshot_call_count > 1 and self.verification_started is not None:
            self.verification_started.set()
            if self.verification_release is not None:
                self.verification_release.wait(timeout=2)

        ip_items = []
        port_items = []
        if state["ip_present"]:
            ip_items.append({"ip": "203.0.113.10"})
        for port in state["ports"]:
            port_items.append({"ip": "203.0.113.10", "port": port})
        return SnapshotRunnerResult(
            status="successful",
            rc=0,
            artifact_dir="/tmp/snapshots/{0}".format(code),
            payload={
                "ip_items": ip_items, "port_items": port_items,
                "address_state": {
                    "vsystems": ["public"],
                    "by_vsystem": {"public": {"203.0.113.10": 32} if state["ip_present"] else {}},
                },
                "application_prefix": "UD_TServe_",
                "application_state": {"applications": [
                    {"name": "UD_TServe_203.0.113.10", "ports": state["ports"],
                     "ip_addresses": [{"ip": "203.0.113.10", "mask": 32}],
                     "rules": [{"name": "1", "ports": state["ports"],
                                "ip_addresses": [{"ip": "203.0.113.10", "mask": 32}]}]},
                ] if state["ports"] else []},
                "application_group_members": ["UD_TServe_203.0.113.10"] if state["ports"] else [],
            },
        )


class WorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage = JobStorage(Path(self.temp_dir.name) / "jobs.sqlite3")
        self.original_parallel_workers = settings.firewall_parallel_workers
        self.original_max_attempts = settings.firewall_child_max_attempts
        self.original_retry_seconds = settings.firewall_reconcile_retry_seconds
        settings.firewall_parallel_workers = 3
        settings.firewall_child_max_attempts = 2
        settings.firewall_reconcile_retry_seconds = 3

    def tearDown(self) -> None:
        settings.firewall_parallel_workers = self.original_parallel_workers
        settings.firewall_child_max_attempts = self.original_max_attempts
        settings.firewall_reconcile_retry_seconds = self.original_retry_seconds
        self.temp_dir.cleanup()

    def make_worker(self, runner, retry_waiter=None) -> JobWorker:
        if retry_waiter is None:
            retry_waiter = lambda _: None
        return JobWorker(
            self.storage,
            runner,
            retry_waiter=retry_waiter,
        )

    def create_job(
        self,
        job_id: str = "job-1",
        firewall_targets=("TEST-FW",),
        action: str = "allow",
        ports=None,
        target_ip: str = "203.0.113.10",
        created_at: str = "2026-06-05T00:00:00+00:00",
    ) -> None:
        target_codes = list(firewall_targets)
        self.storage.create_job(
            {
                "job_id": job_id,
                "status": "pending",
                "action": action,
                "target_ip": target_ip,
                "mask": 32,
                "ports": [12001] if ports is None else ports,
                "description": None,
                "client_request_id": None,
                "principal_subject": "employee-a",
                "principal_id": "subject-a",
                "principal_key_id": "key-a",
                "principal_type": "employee",
                "auth_type": "secret_key",
                "runner_status": None,
                "runner_rc": None,
                "error_message": None,
                "created_at": created_at,
                "started_at": None,
                "finished_at": None,
                "artifact_dir": "/tmp/artifacts/{0}".format(job_id),
                "local_tmp_dir": "/tmp/jobs/{0}".format(job_id),
                "firewall_targets": target_codes,
                "desired_state": None,
                "state_version": None,
                "next_attempt_at": None,
            },
            target_codes,
        )

    def test_rfc1918_allow_is_rejected_before_firewall_access(self) -> None:
        self.create_job(target_ip="192.168.30.40")
        runner = FakeRunner(
            states={"TEST-FW": {"ip_present": False, "ports": []}},
        )

        self.assertTrue(self.make_worker(runner).run_once())

        job = self.storage.get_job("job-1")
        target = self.storage.list_job_targets("job-1")[0]
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["runner_status"], "policy_rejected")
        self.assertEqual(job["runner_rc"], 2)
        self.assertIn("RFC1918 private IPv4", job["error_message"])
        self.assertEqual(target["status"], "failed")
        self.assertEqual(target["runner_status"], "policy_rejected")
        self.assertEqual(runner.snapshot_calls, [])
        self.assertEqual(runner.jobs, [])

    def test_successful_job_records_verified_child_and_desired_state(self) -> None:
        self.create_job()
        runner = FakeRunner(
            states={"TEST-FW": {"ip_present": False, "ports": []}},
        )
        worker = self.make_worker(runner)

        self.assertTrue(worker.run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "successful")
        self.assertEqual(job["runner_rc"], 0)
        self.assertEqual(
            job["desired_state"],
            {"ip_present": True, "ports": [12001], "version": 1},
        )
        self.assertEqual(job["state_version"], 1)
        self.assertIsNotNone(job["started_at"])
        self.assertIsNotNone(job["finished_at"])

        targets = self.storage.list_job_targets("job-1")
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["status"], "verified")
        self.assertEqual(targets[0]["attempt_count"], 1)
        self.assertFalse(targets[0]["before_state"]["ip_present"])
        self.assertEqual(targets[0]["before_state"]["ports"], [])
        self.assertTrue(targets[0]["observed_state"]["ip_present"])
        self.assertEqual(targets[0]["observed_state"]["ports"], [12001])
        self.assertEqual(len(runner.jobs), 1)
        self.assertEqual(runner.snapshot_calls, [("state", "TEST-FW"), ("state", "TEST-FW")])

    def test_three_firewall_children_apply_in_parallel(self) -> None:
        codes = ("PG-FW", "PG-FW-1", "IDC-FW")
        self.create_job(firewall_targets=codes)
        runner = FakeRunner(
            states={
                code: {"ip_present": False, "ports": []}
                for code in codes
            },
            mutation_barrier=threading.Barrier(len(codes)),
        )

        self.assertTrue(self.make_worker(runner).run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "successful")
        self.assertEqual(runner.max_active_mutations, 3)
        self.assertEqual(
            {target["status"] for target in self.storage.list_job_targets("job-1")},
            {"verified"},
        )

    def test_parent_reports_verifying_while_single_child_postcheck_runs(self) -> None:
        self.create_job()
        verification_started = threading.Event()
        verification_release = threading.Event()
        runner = FakeRunner(
            states={"TEST-FW": {"ip_present": False, "ports": []}},
            verification_started=verification_started,
            verification_release=verification_release,
        )
        worker = self.make_worker(runner)
        worker_thread = threading.Thread(target=worker.run_once)
        worker_thread.start()
        try:
            self.assertTrue(verification_started.wait(timeout=2))
            parent = self.storage.get_job("job-1")
            child = self.storage.list_job_targets("job-1")[0]
            self.assertEqual(parent["status"], "verifying")
            self.assertEqual(parent["runner_status"], "verifying")
            self.assertEqual(child["status"], "verifying")
        finally:
            verification_release.set()
            worker_thread.join(timeout=2)

        self.assertFalse(worker_thread.is_alive())
        self.assertEqual(self.storage.get_job("job-1")["status"], "successful")

    def test_partial_target_failure_retries_inside_same_parent(self) -> None:
        codes = ("PG-FW", "PG-FW-1", "IDC-FW")
        self.create_job(firewall_targets=codes)
        runner = FakeRunner(
            states={
                code: {"ip_present": False, "ports": []}
                for code in codes
            },
            failure_counts={"IDC-FW": 1},
        )
        retry_delays = []
        worker = self.make_worker(runner, retry_delays.append)

        self.assertTrue(worker.run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "successful")
        self.assertEqual(job["runner_status"], "successful")
        self.assertIsNone(job["next_attempt_at"])
        self.assertIsNotNone(job["finished_at"])
        self.assertEqual(retry_delays, [3.0])
        targets = {
            target["firewall_code"]: target
            for target in self.storage.list_job_targets("job-1")
        }
        self.assertEqual(
            {target["status"] for target in targets.values()},
            {"verified"},
        )
        self.assertEqual(targets["PG-FW"]["attempt_count"], 1)
        self.assertEqual(targets["PG-FW-1"]["attempt_count"], 1)
        self.assertEqual(targets["IDC-FW"]["attempt_count"], 2)
        mutation_codes = [code for _, code in runner.jobs]
        self.assertEqual(mutation_codes.count("PG-FW"), 1)
        self.assertEqual(mutation_codes.count("PG-FW-1"), 1)
        self.assertEqual(mutation_codes.count("IDC-FW"), 2)

    def test_retryable_failure_stops_after_two_total_attempts(self) -> None:
        self.create_job()
        runner = FakeRunner(
            states={"TEST-FW": {"ip_present": False, "ports": []}},
            failed_codes={"TEST-FW"},
        )
        retry_delays = []
        worker = self.make_worker(runner, retry_delays.append)

        self.assertTrue(worker.run_once())

        final = self.storage.get_job("job-1")
        target = self.storage.list_job_targets("job-1")[0]
        self.assertEqual(final["status"], "failed")
        self.assertEqual(final["runner_status"], "attempt_limit_reached")
        self.assertIsNone(final["next_attempt_at"])
        self.assertIsNotNone(final["finished_at"])
        self.assertEqual(target["status"], "failed")
        self.assertEqual(target["attempt_count"], 2)
        self.assertEqual(len(runner.jobs), 2)
        self.assertEqual(retry_delays, [3.0])
        self.assertFalse(worker.run_once())
        self.assertEqual(len(runner.jobs), 2)

    def test_retry_with_existing_baseline_runs_one_final_snapshot_only(self) -> None:
        self.create_job()
        self.storage.save_desired_access_state(
            target_ip="203.0.113.10",
            ip_present=False,
            ports=[],
            source_job_id="baseline-import",
            updated_at="2026-06-04T00:00:00+00:00",
        )
        runner = FakeRunner(
            states={"TEST-FW": {"ip_present": False, "ports": []}},
            failure_counts={"TEST-FW": 1},
        )
        retry_delays = []
        worker = self.make_worker(runner, retry_delays.append)

        self.assertTrue(worker.run_once())

        self.assertEqual(self.storage.get_job("job-1")["status"], "successful")
        self.assertEqual(len(runner.jobs), 2)
        self.assertEqual(retry_delays, [3.0])
        self.assertEqual(runner.snapshot_calls, [("state", "TEST-FW")])

    def test_matching_config_cannot_override_commit_or_save_failure(self) -> None:
        self.create_job(action="allow_ip", ports=[])
        self.storage.save_desired_access_state(
            target_ip="203.0.113.10",
            ip_present=False,
            ports=[],
            source_job_id="baseline-import",
            updated_at="2026-06-04T00:00:00+00:00",
        )
        runner = FakeRunner(
            states={"TEST-FW": {"ip_present": False, "ports": []}},
            failed_codes={"TEST-FW"},
            failed_after_apply_codes={"TEST-FW"},
        )
        retry_delays = []
        worker = self.make_worker(runner, retry_delays.append)

        self.assertTrue(worker.run_once())

        parent = self.storage.get_job("job-1")
        target = self.storage.list_job_targets("job-1")[0]
        self.assertEqual(parent["status"], "failed")
        self.assertEqual(target["status"], "failed")
        self.assertEqual(target["runner_status"], "failed")
        self.assertEqual(target["attempt_count"], 2)
        self.assertEqual(retry_delays, [3.0])
        self.assertEqual(runner.snapshot_calls, [])

    def test_late_failure_is_finalized_on_retry_even_when_state_already_matches(self) -> None:
        self.create_job()
        runner = FakeRunner(failed_after_apply_codes={"TEST-FW"})

        def recover(_seconds):
            runner.failed_after_apply_codes.clear()

        self.make_worker(runner, recover).run_once()
        self.assertEqual(self.storage.get_job("job-1")["status"], "successful")
        self.assertEqual(len(runner.jobs), 2)
        self.assertTrue(all(job["force_finalize"] for job, _ in runner.jobs))

    def test_followup_port_job_repairs_failed_previous_desired_ports(self) -> None:
        self.create_job(ports=[12001])
        runner = FakeRunner(failed_codes={"TEST-FW"})
        worker = self.make_worker(runner)
        worker.run_once()
        self.assertEqual(self.storage.get_job("job-1")["status"], "failed")
        runner.failed_codes.clear()
        self.create_job(job_id="job-2", ports=[12002], created_at="2026-06-05T00:00:01+00:00")
        worker.run_once()
        self.assertEqual(self.storage.get_job("job-2")["status"], "successful")
        self.assertEqual(runner.states["TEST-FW"]["ports"], [12001, 12002])
        self.assertEqual(runner.jobs[-1][0]["desired_state"]["ports"], [12001, 12002])

    def test_crash_during_last_attempt_does_not_turn_matching_config_into_success(self) -> None:
        self.create_job()
        desired = {"ip_present": True, "ports": [12001], "version": 1}
        self.storage.update_job("job-1", {"status": "applying", "desired_state": desired, "state_version": 1})
        self.storage.update_job_target("job-1", "TEST-FW", {"status": "applying", "attempt_count": 2})
        runner = FakeRunner(states={"TEST-FW": {"ip_present": True, "ports": [12001]}})
        self.make_worker(runner).run_once()
        self.assertEqual(self.storage.get_job("job-1")["status"], "failed")
        self.assertEqual(runner.jobs, [])

    def test_application_capacity_error_requires_manual_intervention_immediately(self) -> None:
        self.create_job()
        capacity_error = (
            "Error: The number of user-defined applications reached the upper limit. "
            "No more user-defined applications can be created."
        )
        runner = FakeRunner(
            states={"TEST-FW": {"ip_present": False, "ports": []}},
            failed_codes={"TEST-FW"},
            failure_messages={"TEST-FW": capacity_error},
        )
        worker = self.make_worker(runner)

        self.assertTrue(worker.run_once())

        parent = self.storage.get_job("job-1")
        target = self.storage.list_job_targets("job-1")[0]
        self.assertEqual(parent["status"], "manual_intervention_required")
        self.assertEqual(parent["runner_status"], "manual_intervention_required")
        self.assertIn("upper limit", parent["error_message"])
        self.assertIsNone(parent["next_attempt_at"])
        self.assertIsNotNone(parent["finished_at"])
        self.assertEqual(target["status"], "manual_intervention_required")
        self.assertEqual(target["runner_status"], "manual_intervention_required")
        self.assertEqual(target["attempt_count"], 1)
        self.assertEqual(target["error_message"], capacity_error)
        self.assertEqual(len(runner.jobs), 1)
        self.assertFalse(worker.run_once())

    def test_runner_success_without_verified_state_is_not_reported_as_success(self) -> None:
        settings.firewall_child_max_attempts = 1
        self.create_job()
        runner = FakeRunner(
            states={"TEST-FW": {"ip_present": False, "ports": []}},
            no_op_codes={"TEST-FW"},
        )

        self.assertTrue(self.make_worker(runner).run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["runner_status"], "attempt_limit_reached")
        target = self.storage.list_job_targets("job-1")[0]
        self.assertEqual(target["status"], "failed")
        self.assertEqual(target["runner_status"], "verification_failed")
        self.assertEqual(target["runner_rc"], 0)
        self.assertEqual(
            target["error_message"],
            "Observed state does not match desired state.",
        )

    def test_preflight_failure_stops_before_any_mutation(self) -> None:
        codes = ("PG-FW", "IDC-FW")
        self.create_job(firewall_targets=codes)
        runner = FakeRunner(
            states={code: {"ip_present": False, "ports": []} for code in codes},
            snapshot_failed_codes={"IDC-FW"},
        )

        self.assertTrue(self.make_worker(runner).run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "reconciling")
        self.assertEqual(job["runner_status"], "precheck_retry_scheduled")
        self.assertIsNotNone(job["next_attempt_at"])
        self.assertEqual(runner.jobs, [])

    def test_precheck_retry_limit_is_persisted_and_unblocks_later_job(self) -> None:
        self.create_job()
        self.create_job(job_id="later", created_at="2026-06-05T00:00:01+00:00")
        runner = FakeRunner(snapshot_failed_codes={"TEST-FW"})
        with patch.object(settings, "precheck_max_attempts", 2):
            worker = self.make_worker(runner)
            worker.run_once()
            self.assertEqual(self.storage.get_job("job-1")["precheck_attempt_count"], 1)
            self.storage.update_job("job-1", {"next_attempt_at": "2000-01-01T00:00:00+00:00"})
            self.make_worker(runner).run_once()
        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["runner_status"], "precheck_attempt_limit_reached")
        self.assertEqual(job["precheck_attempt_count"], 2)
        self.assertIsNone(job["next_attempt_at"])
        self.assertEqual(self.storage.claim_next_runnable_job("2026-10-27T00:00:00+00:00")["job_id"], "later")
        self.assertEqual(runner.jobs, [])

    def test_cancel_during_precheck_does_not_write_ledger_or_firewall(self) -> None:
        self.create_job()
        runner = FakeRunner()
        original_snapshot = runner.run_firewall_snapshot

        def cancel_while_querying(*args, **kwargs):
            self.assertTrue(self.storage.cancel_job("job-1", "2026-10-27T00:00:00+00:00"))
            return original_snapshot(*args, **kwargs)

        runner.run_firewall_snapshot = cancel_while_querying
        self.make_worker(runner).run_once()
        self.assertEqual(self.storage.get_job("job-1")["status"], "canceled")
        self.assertIsNone(self.storage.get_desired_access_state("203.0.113.10"))
        self.assertEqual(runner.jobs, [])

    def test_expired_resumed_job_cannot_access_device(self) -> None:
        self.create_job()
        self.storage.update_job("job-1", {"status": "running", "deadline_at": "2000-01-01T00:00:00+00:00"})
        runner = FakeRunner()
        self.make_worker(runner).run_once()
        self.assertEqual(self.storage.get_job("job-1")["runner_status"], "timed_out")
        self.assertEqual(runner.snapshot_calls, [])
        self.assertEqual(runner.jobs, [])

    def test_deadline_expires_during_retry_backoff_without_second_mutation(self) -> None:
        self.create_job()
        runner = FakeRunner(failed_codes={"TEST-FW"})
        expired = False

        def expire(_seconds):
            nonlocal expired
            expired = True

        worker = self.make_worker(runner, expire)
        worker._remaining_job_seconds = lambda job: -1 if expired else 60
        worker.run_once()
        self.assertEqual(self.storage.get_job("job-1")["runner_status"], "timed_out")
        self.assertEqual(len(runner.jobs), 1)

    def test_deadline_expiring_during_final_verification_cannot_report_success(self) -> None:
        self.create_job()
        runner = FakeRunner()
        original_snapshot = runner.run_firewall_snapshot
        expired = False

        def expire_after_verification(*args, **kwargs):
            nonlocal expired
            result = original_snapshot(*args, **kwargs)
            if runner.jobs:
                expired = True
            return result

        runner.run_firewall_snapshot = expire_after_verification
        worker = self.make_worker(runner)
        worker._remaining_job_seconds = lambda job: -1 if expired else 60
        worker.run_once()
        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["runner_status"], "timed_out")

    def test_internal_retry_finishes_before_a_different_ip_parent_can_run(self) -> None:
        codes = ("PG-FW", "PG-FW-1", "IDC-FW")
        self.create_job(job_id="job-retry", firewall_targets=codes)
        self.create_job(
            job_id="job-other-ip",
            firewall_targets=codes,
            action="deny",
            ports=[],
            target_ip="203.0.113.11",
            created_at="2026-06-05T00:00:01+00:00",
        )
        runner = FakeRunner(
            states={code: {"ip_present": False, "ports": []} for code in codes},
            failure_counts={"IDC-FW": 1},
        )
        retry_started = threading.Event()
        retry_release = threading.Event()

        def wait_for_retry(_seconds):
            retry_started.set()
            retry_release.wait(timeout=2)

        worker = self.make_worker(runner, wait_for_retry)
        worker_thread = threading.Thread(target=worker.run_once)
        worker_thread.start()
        try:
            self.assertTrue(retry_started.wait(timeout=2))
            retrying = self.storage.get_job("job-retry")
            self.assertEqual(retrying["status"], "reconciling")
            self.assertEqual(
                retrying["runner_status"],
                "partially_successful_retrying",
            )
            self.assertIsNone(retrying["next_attempt_at"])
            self.assertEqual(self.storage.get_job("job-other-ip")["status"], "pending")
        finally:
            retry_release.set()
            worker_thread.join(timeout=2)

        self.assertFalse(worker_thread.is_alive())
        self.assertEqual(self.storage.get_job("job-retry")["status"], "successful")
        self.assertEqual(self.storage.get_job("job-other-ip")["status"], "pending")
        self.assertTrue(worker.run_once())
        self.assertEqual(self.storage.get_job("job-other-ip")["status"], "successful")

    def test_preflight_rejects_drift_without_a_desired_state_baseline(self) -> None:
        codes = ("PG-FW", "IDC-FW")
        self.create_job(firewall_targets=codes)
        runner = FakeRunner(
            states={
                "PG-FW": {"ip_present": True, "ports": [12002]},
                "IDC-FW": {"ip_present": True, "ports": [12003]},
            },
        )

        self.assertTrue(self.make_worker(runner).run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "failed")
        self.assertIn("inconsistent state", job["error_message"])
        self.assertEqual(runner.jobs, [])

    def test_full_deny_cleans_drift_without_a_ledger_or_consistent_baseline(self) -> None:
        codes = ("PG-FW", "PG-FW-1", "IDC-FW")
        self.create_job(action="deny", ports=[], firewall_targets=codes)
        runner = FakeRunner(states={
            "PG-FW": {"ip_present": True, "ports": [443]},
            "PG-FW-1": {"ip_present": False, "ports": [8443]},
            "IDC-FW": {"ip_present": True, "ports": []},
        })
        self.assertTrue(self.make_worker(runner).run_once())
        job = self.storage.get_job("job-1", include_targets=True)
        self.assertEqual(job["status"], "successful")
        self.assertEqual(job["precheck_attempt_count"], 0)
        self.assertFalse(job["desired_state"]["ip_present"])
        self.assertEqual(job["desired_state"]["ports"], [])
        self.assertEqual(len(runner.jobs), 3)
        self.assertEqual(len(runner.snapshot_calls), 3)
        self.assertEqual({target["status"] for target in job["target_results"]}, {"verified"})
        self.assertTrue(all(state == {"ip_present": False, "ports": []} for state in runner.states.values()))

    def test_full_deny_still_fails_when_a_node_retains_orphan_application(self) -> None:
        codes = ("PG-FW", "IDC-FW")
        self.create_job(action="deny", ports=[], firewall_targets=codes)
        runner = FakeRunner(
            states={"IDC-FW": {"ip_present": False, "ports": [443]}},
            no_op_codes={"IDC-FW"},
        )
        self.make_worker(runner).run_once()
        self.assertEqual(self.storage.get_job("job-1")["status"], "failed")
        self.assertEqual(runner.states["IDC-FW"]["ports"], [443])
        self.assertTrue(runner.jobs)

    def test_ip_only_deny_keeps_rejecting_drift_without_a_ledger(self) -> None:
        codes = ("PG-FW", "IDC-FW")
        self.create_job(action="deny_ip", ports=[], firewall_targets=codes)
        runner = FakeRunner(states={"PG-FW": {"ip_present": True, "ports": [443]}})
        self.make_worker(runner).run_once()
        self.assertEqual(self.storage.get_job("job-1")["status"], "failed")
        self.assertEqual(runner.jobs, [])

    def test_interrupted_parent_resumes_same_desired_version_and_repairs_only_missing_target(self) -> None:
        codes = ("PG-FW", "PG-FW-1", "IDC-FW")
        self.create_job(firewall_targets=codes)
        desired = self.storage.save_desired_access_state(
            target_ip="203.0.113.10",
            ip_present=True,
            ports=[12001],
            source_job_id="job-1",
            updated_at="2026-06-05T00:01:00+00:00",
        )
        self.storage.update_job(
            "job-1",
            {
                "status": "applying",
                "started_at": "2026-06-05T00:01:00+00:00",
                "desired_state": {
                    "ip_present": True,
                    "ports": [12001],
                    "version": desired["version"],
                },
                "state_version": desired["version"],
            },
        )
        for code in ("PG-FW", "PG-FW-1"):
            self.storage.update_job_target(
                "job-1",
                code,
                {
                    "status": "verified",
                    "runner_status": "successful",
                    "runner_rc": 0,
                    "desired_state": {
                        "ip_present": True,
                        "ports": [12001],
                        "version": desired["version"],
                    },
                    "observed_state": {
                        "ip_present": True,
                        "ports": [12001],
                    },
                },
            )
        runner = FakeRunner(
            states={
                "PG-FW": {"ip_present": True, "ports": [12001]},
                "PG-FW-1": {"ip_present": True, "ports": [12001]},
                "IDC-FW": {"ip_present": False, "ports": []},
            },
        )

        self.assertTrue(self.make_worker(runner).run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "successful")
        self.assertEqual(job["state_version"], 1)
        self.assertEqual(
            [code for _, code in runner.jobs],
            ["IDC-FW"],
        )
        self.assertEqual(
            self.storage.get_desired_access_state("203.0.113.10")["version"],
            1,
        )
        targets = {
            target["firewall_code"]: target
            for target in self.storage.list_job_targets("job-1")
        }
        self.assertEqual(targets["PG-FW"]["status"], "verified")
        self.assertEqual(targets["PG-FW-1"]["status"], "verified")
        self.assertEqual(targets["IDC-FW"]["status"], "verified")

    def test_empty_queue_returns_without_running_ansible(self) -> None:
        runner = FakeRunner()
        worker = self.make_worker(runner)

        self.assertFalse(worker.run_once())
        self.assertEqual(runner.jobs, [])


if __name__ == "__main__":
    unittest.main()
