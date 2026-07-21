import tempfile
import threading
import unittest
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
        snapshot_failed_codes=None,
        mutation_barrier=None,
    ):
        self.states = {
            code: {
                "ip_present": bool(state["ip_present"]),
                "ports": sorted(state["ports"]),
            }
            for code, state in (states or {}).items()
        }
        self.failed_codes = set(failed_codes or [])
        self.snapshot_failed_codes = set(snapshot_failed_codes or [])
        self.mutation_barrier = mutation_barrier
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
            if code in self.failed_codes:
                return RunnerResult(
                    status="failed",
                    rc=2,
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
                state["ports"] = sorted(ports)

            return RunnerResult(
                status="successful",
                rc=0,
                artifact_dir="/tmp/artifacts/{0}/{1}".format(job["job_id"], code),
            )
        finally:
            with self._lock:
                self.active_mutations -= 1

    def run_firewall_snapshot(self, snapshot_mode="snapshot", firewall_code=None):
        code = str(firewall_code)
        with self._lock:
            self.snapshot_calls.append((snapshot_mode, code))
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

        ip_items = []
        port_items = []
        if state["ip_present"]:
            ip_items.append({"ip": "192.168.5.224"})
        for port in state["ports"]:
            port_items.append({"ip": "192.168.5.224", "port": port})
        return SnapshotRunnerResult(
            status="successful",
            rc=0,
            artifact_dir="/tmp/snapshots/{0}".format(code),
            payload={"ip_items": ip_items, "port_items": port_items},
        )


class WorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage = JobStorage(Path(self.temp_dir.name) / "jobs.sqlite3")
        self.original_parallel_workers = settings.firewall_parallel_workers
        self.original_max_attempts = settings.firewall_child_max_attempts
        settings.firewall_parallel_workers = 3
        settings.firewall_child_max_attempts = 2

    def tearDown(self) -> None:
        settings.firewall_parallel_workers = self.original_parallel_workers
        settings.firewall_child_max_attempts = self.original_max_attempts
        self.temp_dir.cleanup()

    def create_job(
        self,
        job_id: str = "job-1",
        firewall_targets=("TEST-FW",),
        action: str = "allow",
        ports=None,
    ) -> None:
        target_codes = list(firewall_targets)
        self.storage.create_job(
            {
                "job_id": job_id,
                "status": "pending",
                "action": action,
                "target_ip": "192.168.5.224",
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
                "created_at": "2026-06-05T00:00:00+00:00",
                "started_at": None,
                "finished_at": None,
                "artifact_dir": "/tmp/artifacts/{0}".format(job_id),
                "local_tmp_dir": "/tmp/jobs/{0}".format(job_id),
                "firewall_targets": target_codes,
                "desired_state": None,
                "state_version": None,
            },
            target_codes,
        )

    def test_successful_job_records_verified_child_and_desired_state(self) -> None:
        self.create_job()
        runner = FakeRunner(
            states={"TEST-FW": {"ip_present": False, "ports": []}},
        )
        worker = JobWorker(self.storage, runner)

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
        self.assertEqual(targets[0]["before_state"], {"ip_present": False, "ports": []})
        self.assertEqual(
            targets[0]["observed_state"],
            {"ip_present": True, "ports": [12001]},
        )
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

        self.assertTrue(JobWorker(self.storage, runner).run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "successful")
        self.assertEqual(runner.max_active_mutations, 3)
        self.assertEqual(
            {target["status"] for target in self.storage.list_job_targets("job-1")},
            {"verified"},
        )

    def test_partial_target_failure_requires_manual_intervention(self) -> None:
        codes = ("PG-FW", "PG-FW-1", "IDC-FW")
        self.create_job(firewall_targets=codes)
        runner = FakeRunner(
            states={
                code: {"ip_present": False, "ports": []}
                for code in codes
            },
            failed_codes={"IDC-FW"},
        )

        self.assertTrue(JobWorker(self.storage, runner).run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "manual_intervention_required")
        self.assertEqual(job["runner_status"], "partially_successful")
        self.assertIn("IDC-FW", job["error_message"])
        targets = {
            target["firewall_code"]: target
            for target in self.storage.list_job_targets("job-1")
        }
        self.assertEqual(targets["PG-FW"]["status"], "verified")
        self.assertEqual(targets["PG-FW-1"]["status"], "verified")
        self.assertEqual(targets["IDC-FW"]["status"], "failed")
        self.assertEqual(targets["IDC-FW"]["attempt_count"], 2)

    def test_preflight_failure_stops_before_any_mutation(self) -> None:
        codes = ("PG-FW", "IDC-FW")
        self.create_job(firewall_targets=codes)
        runner = FakeRunner(
            states={code: {"ip_present": False, "ports": []} for code in codes},
            snapshot_failed_codes={"IDC-FW"},
        )

        self.assertTrue(JobWorker(self.storage, runner).run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["runner_status"], "precheck_failed")
        self.assertEqual(runner.jobs, [])

    def test_preflight_rejects_drift_without_a_desired_state_baseline(self) -> None:
        codes = ("PG-FW", "IDC-FW")
        self.create_job(firewall_targets=codes)
        runner = FakeRunner(
            states={
                "PG-FW": {"ip_present": True, "ports": [12002]},
                "IDC-FW": {"ip_present": True, "ports": [12003]},
            },
        )

        self.assertTrue(JobWorker(self.storage, runner).run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "failed")
        self.assertIn("inconsistent state", job["error_message"])
        self.assertEqual(runner.jobs, [])

    def test_interrupted_parent_resumes_same_desired_version_and_repairs_only_missing_target(self) -> None:
        codes = ("PG-FW", "PG-FW-1", "IDC-FW")
        self.create_job(firewall_targets=codes)
        desired = self.storage.save_desired_access_state(
            target_ip="192.168.5.224",
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
        runner = FakeRunner(
            states={
                "PG-FW": {"ip_present": True, "ports": [12001]},
                "PG-FW-1": {"ip_present": True, "ports": [12001]},
                "IDC-FW": {"ip_present": False, "ports": []},
            },
        )

        self.assertTrue(JobWorker(self.storage, runner).run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "successful")
        self.assertEqual(job["state_version"], 1)
        self.assertEqual(
            [code for _, code in runner.jobs],
            ["IDC-FW"],
        )
        self.assertEqual(
            self.storage.get_desired_access_state("192.168.5.224")["version"],
            1,
        )
        targets = {
            target["firewall_code"]: target
            for target in self.storage.list_job_targets("job-1")
        }
        self.assertEqual(targets["PG-FW"]["runner_status"], "already_converged")
        self.assertEqual(targets["PG-FW-1"]["runner_status"], "already_converged")
        self.assertEqual(targets["IDC-FW"]["status"], "verified")

    def test_empty_queue_returns_without_running_ansible(self) -> None:
        runner = FakeRunner()
        worker = JobWorker(self.storage, runner)

        self.assertFalse(worker.run_once())
        self.assertEqual(runner.jobs, [])


if __name__ == "__main__":
    unittest.main()
