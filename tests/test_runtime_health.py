import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from api.config import settings
from api.runtime_health import readiness_report
from api.storage import JobStorage
from api.worker import JobWorker
from test_worker import FakeRunner


class RuntimeHealthTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.storage = JobStorage(Path(self.temp.name) / "jobs.sqlite3")
        self.now = datetime.now(timezone.utc)

    def heartbeat(self, **changes):
        record = {
            "worker_id": "worker-1", "heartbeat_at": self.now.isoformat(),
            "progress_at": self.now.isoformat(),
            "progress_deadline_at": (self.now + timedelta(seconds=60)).isoformat(),
            "phase": "idle", "job_id": None,
            "last_poll_at": self.now.isoformat(),
        }
        self.storage.record_worker_heartbeat({**record, **changes})

    def test_no_worker_and_stopped_worker_are_not_ready(self):
        self.assertEqual(readiness_report(self.storage, self.now)["status"], "not_ready")
        self.heartbeat(phase="stopped")
        self.assertEqual(readiness_report(self.storage, self.now)["checks"]["worker"], "unavailable")

    def test_fresh_idle_worker_is_ready_and_reports_queue_age(self):
        self.heartbeat()
        report = readiness_report(self.storage, self.now)
        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["queue"]["pending_count"], 0)

    def test_pending_queue_age_is_reported_without_failing_healthy_worker(self):
        self.heartbeat()
        self.storage.create_job({
            "job_id": "queued", "status": "pending", "action": "deny", "target_ip": "203.0.113.10",
            "mask": 32, "ports": [], "created_at": (self.now - timedelta(minutes=5)).isoformat(),
            "firewall_targets": ["TEST-FW"], "local_tmp_dir": str(Path(self.temp.name) / "job"),
        })
        report = readiness_report(self.storage, self.now)
        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["queue"]["pending_count"], 1)
        self.assertEqual(report["queue"]["oldest_pending_age_seconds"], 300)

    def test_stale_heartbeat_and_live_but_stalled_execution_are_unready(self):
        self.heartbeat(heartbeat_at=(self.now - timedelta(minutes=2)).isoformat())
        self.assertEqual(readiness_report(self.storage, self.now)["status"], "not_ready")
        self.heartbeat(progress_deadline_at=(self.now - timedelta(minutes=2)).isoformat())
        self.assertEqual(readiness_report(self.storage, self.now)["status"], "not_ready")

    def test_normal_long_execution_does_not_need_frequent_stage_changes(self):
        self.heartbeat(
            phase="applying", progress_at=(self.now - timedelta(minutes=8)).isoformat(),
            progress_deadline_at=(self.now + timedelta(minutes=6)).isoformat(),
        )
        self.assertEqual(readiness_report(self.storage, self.now)["status"], "ready")

    def test_database_failure_is_not_ready_without_recreating_database(self):
        self.heartbeat()
        self.storage.database_path.unlink()
        report = readiness_report(self.storage, self.now)
        self.assertEqual(report["checks"]["database"], "unavailable")
        self.assertFalse(self.storage.database_path.exists())

    def test_readonly_database_cannot_pass_readiness(self):
        import sqlite3
        original_connect = sqlite3.connect

        def readonly(*args, **kwargs):
            kwargs["uri"] = True
            return original_connect(self.storage.database_path.as_uri() + "?mode=ro", **kwargs)

        self.heartbeat()
        with patch("api.storage.sqlite3.connect", side_effect=readonly):
            self.assertEqual(readiness_report(self.storage, self.now)["checks"]["database"], "unavailable")

    def test_commit_failure_is_reported_as_database_unavailable(self):
        import sqlite3
        original_connect = sqlite3.connect

        class FullDiskConnection(sqlite3.Connection):
            def commit(self):
                raise sqlite3.OperationalError("database or disk is full")

        def full_disk(*args, **kwargs):
            return original_connect(*args, **kwargs, factory=FullDiskConnection)

        self.heartbeat()
        with patch("api.storage.sqlite3.connect", side_effect=full_disk):
            self.assertEqual(readiness_report(self.storage)["checks"]["database"], "unavailable")

    def active_job(self, deadline):
        self.storage.create_job({
            "job_id": "active-job", "status": "applying", "action": "deny", "target_ip": "203.0.113.10",
            "mask": 32, "ports": [], "created_at": self.now.isoformat(), "deadline_at": deadline,
            "firewall_targets": ["TEST-FW"], "local_tmp_dir": str(Path(self.temp.name) / "job"),
        })

    def test_idle_worker_does_not_hide_stalled_owner_and_recovery_clears_it(self):
        self.active_job((self.now + timedelta(hours=1)).isoformat())
        self.heartbeat(job_id="active-job", phase="applying", progress_deadline_at=(self.now - timedelta(minutes=2)).isoformat())
        self.heartbeat(worker_id="worker-2")
        report = readiness_report(self.storage, self.now)
        self.assertEqual(report["status"], "not_ready")
        self.assertEqual(report["worker"]["stalled_active_job_count"], 1)
        self.heartbeat(worker_id="worker-2", phase="applying", job_id="active-job")
        self.assertEqual(readiness_report(self.storage, self.now)["status"], "ready")

    def test_overdue_job_is_unready_even_with_fresh_idle_worker(self):
        self.active_job((self.now - timedelta(minutes=2)).isoformat())
        self.heartbeat()
        report = readiness_report(self.storage, self.now)
        self.assertEqual(report["status"], "not_ready")
        self.assertTrue(report["worker"]["execution_deadline_exceeded"])

    def test_recovered_precheck_backoff_does_not_inherit_crashed_owner(self):
        self.active_job((self.now + timedelta(hours=1)).isoformat())
        self.storage.update_job("active-job", {"action": "allow"})
        self.heartbeat(
            worker_id="crashed-worker", phase="prechecking", job_id="active-job",
            heartbeat_at=(self.now - timedelta(minutes=2)).isoformat(),
        )
        worker = JobWorker(self.storage, FakeRunner(snapshot_failed_codes={"TEST-FW"}))
        self.assertTrue(worker.run_once())
        worker.heartbeat._publish()
        job = self.storage.get_job("active-job")
        self.assertEqual(job["runner_status"], "precheck_retry_scheduled")
        self.assertIsNotNone(job["next_attempt_at"])
        report = readiness_report(self.storage)
        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["worker"]["stalled_active_job_count"], 0)

        # Reserving execution clears next_attempt_at: an idle peer must no
        # longer hide a stalled executor, even after a normal backoff.
        self.storage.update_job("active-job", {"next_attempt_at": self.now.isoformat()})
        self.storage.claim_next_runnable_job(datetime.now(timezone.utc).isoformat())
        self.assertEqual(readiness_report(self.storage)["status"], "not_ready")

    def test_scheduled_precheck_backoff_still_respects_parent_deadline(self):
        self.active_job((self.now - timedelta(minutes=2)).isoformat())
        self.storage.update_job("active-job", {
            "status": "reconciling", "runner_status": "precheck_retry_scheduled",
            "next_attempt_at": (self.now + timedelta(minutes=1)).isoformat(),
        })
        self.heartbeat()
        report = readiness_report(self.storage, self.now)
        self.assertEqual(report["status"], "not_ready")
        self.assertTrue(report["worker"]["execution_deadline_exceeded"])

    def test_normal_draining_job_is_not_misclassified_as_a_stalled_execution(self):
        self.active_job((self.now + timedelta(hours=1)).isoformat())
        self.heartbeat(phase="draining", job_id="active-job")
        report = readiness_report(self.storage, self.now)
        self.assertEqual(report["status"], "not_ready")
        self.assertEqual(report["worker"]["stalled_active_job_count"], 0)
        self.heartbeat(worker_id="worker-2")
        self.assertEqual(readiness_report(self.storage, self.now)["status"], "ready")

    def test_locked_database_has_a_bounded_probe_and_recovers(self):
        self.heartbeat()
        with self.storage._connect() as held:
            held.execute("begin immediate")
            started = time.monotonic()
            self.assertEqual(readiness_report(self.storage)["status"], "not_ready")
            self.assertLess(time.monotonic() - started, 1)
            held.rollback()
        self.assertEqual(readiness_report(self.storage)["status"], "ready")

    def test_poll_failure_is_unready_despite_live_heartbeat_and_can_recover(self):
        stop, recover = threading.Event(), threading.Event()
        original_claim = self.storage.claim_next_runnable_job

        def claim(*args, **kwargs):
            if not recover.is_set():
                raise RuntimeError("Local poll failure")
            return original_claim(*args, **kwargs)

        with patch.object(self.storage, "claim_next_runnable_job", side_effect=claim), \
                patch.object(settings, "worker_heartbeat_interval_seconds", 0.02), patch("api.worker.logger"):
            worker = JobWorker(self.storage, FakeRunner(), poll_interval=0.01)
            worker.heartbeat.poll_succeeded()
            thread = threading.Thread(target=worker.run_forever, args=(stop,))
            thread.start()
            try:
                time.sleep(0.1)
                self.assertEqual(readiness_report(self.storage)["status"], "not_ready")
                recover.set()
                until = time.monotonic() + 1
                while readiness_report(self.storage)["status"] != "ready" and time.monotonic() < until:
                    time.sleep(0.01)
                self.assertEqual(readiness_report(self.storage)["status"], "ready")
            finally:
                stop.set()
                thread.join(2)
        self.assertFalse(thread.is_alive())

    def test_heartbeat_continues_during_blocked_runner_and_stops_with_worker(self):
        entered, release, stop = threading.Event(), threading.Event(), threading.Event()

        class BlockingRunner(FakeRunner):
            def run_trade_access(self, job, firewall_code=None):
                entered.set()
                if not release.wait(3):
                    raise AssertionError("Local runner fixture was not released")
                return super().run_trade_access(job, firewall_code)

        self.storage.create_job({
            "job_id": "health-job", "status": "pending", "action": "allow", "target_ip": "203.0.113.10",
            "mask": 32, "ports": [443], "created_at": self.now.isoformat(),
            "firewall_targets": ["TEST-FW"], "local_tmp_dir": str(Path(self.temp.name) / "job"),
        })
        with patch.object(settings, "worker_heartbeat_interval_seconds", 0.02), \
                patch.object(settings, "worker_heartbeat_timeout_seconds", 0.15):
            worker = JobWorker(self.storage, BlockingRunner(), poll_interval=0.01)
            thread = threading.Thread(target=worker.run_forever, args=(stop,))
            thread.start()
            try:
                self.assertTrue(entered.wait(2))
                time.sleep(0.3)
                self.assertEqual(readiness_report(self.storage)["status"], "ready")
                stop.set()
                until = time.monotonic() + 1
                while readiness_report(self.storage)["status"] == "ready" and time.monotonic() < until:
                    time.sleep(0.01)
                self.assertEqual(readiness_report(self.storage)["status"], "not_ready")
            finally:
                stop.set()
                release.set()
                thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(readiness_report(self.storage)["status"], "not_ready")

    def test_runner_stall_is_unready_even_while_heartbeat_keeps_updating(self):
        entered, release, stop = threading.Event(), threading.Event(), threading.Event()

        class HungRunner(FakeRunner):
            def run_trade_access(self, job, firewall_code=None):
                entered.set()
                if not release.wait(2):
                    raise AssertionError("Local stalled runner fixture was not released")
                return super().run_trade_access(job, firewall_code)

        self.storage.create_job({
            "job_id": "stalled-job", "status": "pending", "action": "deny", "target_ip": "203.0.113.10",
            "mask": 32, "ports": [], "created_at": self.now.isoformat(),
            "firewall_targets": ["TEST-FW"], "local_tmp_dir": str(Path(self.temp.name) / "job"),
        })
        with patch.object(settings, "worker_heartbeat_interval_seconds", 0.02), \
                patch.object(settings, "worker_heartbeat_timeout_seconds", 0.2), \
                patch.object(settings, "runner_timeout_seconds", 0.05):
            worker = JobWorker(self.storage, HungRunner(), poll_interval=0.01)
            thread = threading.Thread(target=worker.run_forever, args=(stop,))
            thread.start()
            try:
                self.assertTrue(entered.wait(1))
                time.sleep(0.4)
                report = readiness_report(self.storage)
                self.assertEqual(report["status"], "not_ready")
                self.assertLess(report["worker"]["latest_heartbeat_age_seconds"], 0.2)
                self.assertEqual(report["worker"]["stalled_active_job_count"], 1)
            finally:
                stop.set()
                release.set()
                thread.join(3)
        self.assertFalse(thread.is_alive())


if __name__ == "__main__":
    unittest.main()
