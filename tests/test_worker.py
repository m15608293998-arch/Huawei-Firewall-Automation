import tempfile
import unittest
from pathlib import Path

from api.runner_service import RunnerResult
from api.storage import JobStorage
from api.worker import JobWorker


class FakeRunner:
    def __init__(self, result: RunnerResult | None = None, error: Exception | None = None):
        self.result = result
        self.error = error
        self.jobs = []

    def run_trade_access(self, job):
        self.jobs.append(job)
        if self.error is not None:
            raise self.error
        return self.result


class WorkerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage = JobStorage(Path(self.temp_dir.name) / "jobs.sqlite3")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def create_job(self, job_id: str = "job-1") -> None:
        self.storage.create_job(
            {
                "job_id": job_id,
                "status": "pending",
                "action": "allow",
                "target_ip": "192.168.5.224",
                "mask": 32,
                "ports": [12001],
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
            }
        )

    def test_successful_job_updates_persistent_status(self) -> None:
        self.create_job()
        runner = FakeRunner(
            RunnerResult(
                status="successful",
                rc=0,
                artifact_dir="/tmp/artifacts/job-1",
            )
        )
        worker = JobWorker(self.storage, runner)

        self.assertTrue(worker.run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "successful")
        self.assertEqual(job["runner_rc"], 0)
        self.assertIsNotNone(job["started_at"])
        self.assertIsNotNone(job["finished_at"])
        self.assertEqual(len(runner.jobs), 1)

    def test_failed_runner_result_is_recorded(self) -> None:
        self.create_job()
        runner = FakeRunner(
            RunnerResult(
                status="failed",
                rc=2,
                artifact_dir="/tmp/artifacts/job-1",
            )
        )
        worker = JobWorker(self.storage, runner)

        self.assertTrue(worker.run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["runner_rc"], 2)
        self.assertIn("status=failed, rc=2", job["error_message"])

    def test_unexpected_runner_exception_is_recorded(self) -> None:
        self.create_job()
        worker = JobWorker(
            self.storage,
            FakeRunner(error=RuntimeError("runner crashed")),
        )

        self.assertTrue(worker.run_once())

        job = self.storage.get_job("job-1")
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["error_message"], "runner crashed")

    def test_empty_queue_returns_without_running_ansible(self) -> None:
        runner = FakeRunner()
        worker = JobWorker(self.storage, runner)

        self.assertFalse(worker.run_once())
        self.assertEqual(runner.jobs, [])


if __name__ == "__main__":
    unittest.main()
