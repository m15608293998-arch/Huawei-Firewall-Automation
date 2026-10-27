import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from ansible_runner.utils import cleanup_artifact_dir

from api import jobs
from api.auth import Principal
from api.config import settings
from api.runner_service import AnsibleRunnerService
from api.storage import JobStorage
from api.worker import JobWorker


class AuditRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.service = AnsibleRunnerService()
        self.storage = JobStorage(self.root / "jobs.sqlite3")
        self.job = {
            "job_id": "audit-job", "status": "pending", "action": "deny", "target_ip": "203.0.113.10",
            "mask": 32, "ports": [], "principal_id": "user", "created_at": "2026-10-27T00:00:00+00:00",
            "firewall_targets": ["TEST-FW"], "local_tmp_dir": str(self.root / "job"),
        }
        self.storage.create_job(self.job)
        self.user = Principal(subject_id="user", subject="user", auth_type="keycloak", roles=[])
        for context in (
            patch.object(settings, "runner_private_data_dir", self.root / "runner"),
            patch.object(settings, "job_tmp_root", self.root / "tmp"),
            patch.object(jobs, "storage", self.storage),
            patch.object(jobs, "runner_service", self.service),
        ):
            context.start()
            self.addCleanup(context.stop)
        self.calls = []

    def fake_run(self, **kwargs):
        self.calls.append(kwargs)
        run = Path(kwargs["artifact_dir"]) / kwargs["ident"]
        event_dir = run / "job_events"
        event_dir.mkdir(parents=True)
        mutation = kwargs["extravars"]["firewall_workflow_mode"] == "access"
        failed = mutation and sum(call["extravars"]["firewall_workflow_mode"] == "access" for call in self.calls) == 1
        event = {
            "counter": 1, "event": "runner_on_failed" if failed else "runner_on_ok",
            "created": "2026-10-27T00:00:{0:02d}+00:00".format(len(self.calls)),
            "event_data": {"task": "Apply incremental application port changes" if mutation else "Query address-set member before",
                           "res": {"msg": "first attempt failed"} if failed else {}},
        }
        (event_dir / "1-test.json").write_text(json.dumps(event))
        (run / "status").write_text("failed" if failed else "successful")
        # Use the installed Runner rotation routine, including its real 0=off behavior.
        cleanup_artifact_dir(str(run.parent), kwargs.get("rotate_artifacts", 0))
        if not mutation:
            payload = {"items": []}
            if kwargs["extravars"]["snapshot_mode"] == "state":
                payload = {
                    "address_state": {"vsystems": ["public"], "by_vsystem": {"public": {}}},
                    "application_prefix": "UD_TServe_",
                    "application_state": {"applications": []},
                    "application_group_members": [],
                }
            Path(kwargs["extravars"]["snapshot_output_path"]).write_text(json.dumps(payload))
        return types.SimpleNamespace(status="failed" if failed else "successful", rc=2 if failed else 0)

    def test_many_snapshots_cannot_rotate_any_mutation_attempt(self):
        with patch.dict(sys.modules, {"ansible_runner": types.SimpleNamespace(run=self.fake_run)}):
            first = self.service.run_trade_access(self.job, "TEST-FW")
            second = self.service.run_trade_access(self.job, "TEST-FW")
            self.storage.update_job_target("audit-job", "TEST-FW", {"artifact_dir": second.artifact_dir, "attempt_count": 2, "status": "verified"})
            self.storage.update_job("audit-job", {"status": "successful"})
            # Force the old mutation to be the first candidate for real Runner cleanup.
            for result in (first, second):
                os.utime(result.artifact_dir, (1, 1))
            for _ in range(25):
                self.assertEqual(self.service.run_firewall_snapshot("ips", "TEST-FW").rc, 0)
        self.assertTrue((Path(first.artifact_dir) / "job_events/1-test.json").exists())
        report = jobs.get_job_events("audit-job", self.user)
        self.assertEqual(report["audit_status"], "available")
        self.assertEqual(len(report["events"]), 2)
        self.assertIn("first attempt failed", report["events"][0]["message"])
        snapshot_root = Path(self.calls[-1]["artifact_dir"])
        self.assertNotEqual(snapshot_root, Path(first.artifact_dir).parent)
        self.assertLessEqual(len(list(snapshot_root.iterdir())), 20)

    def test_worker_queries_are_kept_with_job_evidence(self):
        with patch.dict(sys.modules, {"ansible_runner": types.SimpleNamespace(run=self.fake_run)}):
            result = self.service.run_firewall_snapshot("state", "TEST-FW", audit_job_id="audit-job", audit_phase="precheck")
        self.assertEqual(self.calls[0]["rotate_artifacts"], 0)
        self.storage.update_job("audit-job", {"status": "failed", "precheck_attempt_count": 1})
        self.storage.update_job_target("audit-job", "TEST-FW", {"artifact_dir": result.artifact_dir})
        self.assertEqual(jobs.get_job_events("audit-job", self.user)["audit_status"], "available")

    def test_missing_audit_is_explicit_instead_of_silent_empty_events(self):
        self.storage.update_job("audit-job", {"status": "failed"})
        self.storage.update_job_target("audit-job", "TEST-FW", {
            "attempt_count": 1, "artifact_dir": str(self.root / "deleted-run"), "status": "failed",
        })
        report = jobs.get_job_events("audit-job", self.user)
        self.assertEqual(report["audit_status"], "unavailable")
        self.assertTrue(report["audit_warnings"])
        self.assertEqual(report["events"], [])

    def test_query_evidence_cannot_hide_a_missing_mutation_attempt(self):
        with patch.dict(sys.modules, {"ansible_runner": types.SimpleNamespace(run=self.fake_run)}):
            first = self.service.run_trade_access(self.job, "TEST-FW")
            second = self.service.run_trade_access(self.job, "TEST-FW")
            self.service.run_firewall_snapshot("state", "TEST-FW", audit_job_id="audit-job")
        self.storage.update_job("audit-job", {"status": "failed"})
        self.storage.update_job_target("audit-job", "TEST-FW", {"attempt_count": 2, "artifact_dir": second.artifact_dir})
        shutil.rmtree(first.artifact_dir)
        report = jobs.get_job_events("audit-job", self.user)
        self.assertEqual(report["audit_status"], "partial")
        self.assertTrue(any("1/2 mutation" in message for message in report["audit_warnings"]))

    def test_legacy_artifact_paths_remain_readable(self):
        legacy = self.root / "runner/TEST-FW/artifacts/audit-job-TEST-FW-123456ab"
        (legacy / "job_events").mkdir(parents=True)
        (legacy / "job_events/1-event.json").write_text(json.dumps({"counter": 1, "event": "playbook_on_stats"}))
        self.storage.update_job("audit-job", {"status": "successful"})
        self.storage.update_job_target("audit-job", "TEST-FW", {"attempt_count": 1, "artifact_dir": str(legacy)})
        report = jobs.get_job_events("audit-job", self.user)
        self.assertEqual(report["audit_status"], "available")
        self.assertEqual(report["events"][0]["event"], "completed")

    def test_missing_final_verification_is_reported(self):
        with patch.dict(sys.modules, {"ansible_runner": types.SimpleNamespace(run=self.fake_run)}):
            self.assertTrue(JobWorker(self.storage, self.service, retry_waiter=lambda _: None).run_once())
        self.assertEqual(self.storage.get_job("audit-job")["status"], "successful")
        self.assertEqual(jobs.get_job_events("audit-job", self.user)["audit_status"], "available")
        root = settings.runner_private_data_dir / "TEST-FW/job_artifacts/audit-job"
        verification = next(root.glob("audit-job-TEST-FW-verify-*"))
        shutil.rmtree(verification)
        report = jobs.get_job_events("audit-job", self.user)
        self.assertEqual(report["audit_status"], "partial")
        self.assertTrue(any("0/1 verification" in message for message in report["audit_warnings"]))

    def test_missing_earlier_verification_is_not_hidden_by_recovered_attempt(self):
        with patch.dict(sys.modules, {"ansible_runner": types.SimpleNamespace(run=self.fake_run)}):
            self.assertTrue(JobWorker(self.storage, self.service, retry_waiter=lambda _: None).run_once())
            root = settings.runner_private_data_dir / "TEST-FW/job_artifacts/audit-job"
            first = next(root.glob("audit-job-TEST-FW-verify-*"))
            # Simulate a crash after target verification but before parent completion.
            self.storage.update_job("audit-job", {"status": "verifying", "finished_at": None})
            self.assertTrue(JobWorker(self.storage, self.service, retry_waiter=lambda _: None).run_once())
        self.assertEqual(jobs.get_job_events("audit-job", self.user)["audit_status"], "available")
        shutil.rmtree(first)
        report = jobs.get_job_events("audit-job", self.user)
        self.assertEqual(report["audit_status"], "partial")
        self.assertTrue(any("1/2 verification" in message for message in report["audit_warnings"]))

    def test_truncated_event_files_are_reported_without_losing_readable_events(self):
        with patch.dict(sys.modules, {"ansible_runner": types.SimpleNamespace(run=self.fake_run)}):
            result = self.service.run_trade_access(self.job, "TEST-FW")
        self.storage.update_job("audit-job", {"status": "failed"})
        self.storage.update_job_target("audit-job", "TEST-FW", {"attempt_count": 1, "artifact_dir": result.artifact_dir})
        event_dir = Path(result.artifact_dir) / "job_events"
        (event_dir / "2-truncated.json").write_text("{")
        report = jobs.get_job_events("audit-job", self.user)
        self.assertEqual(report["audit_status"], "partial")
        self.assertEqual(len(report["events"]), 1)
        (event_dir / "1-test.json").write_text("")
        report = jobs.get_job_events("audit-job", self.user)
        self.assertEqual(report["audit_status"], "unavailable")
        self.assertEqual(report["events"], [])


if __name__ == "__main__":
    unittest.main()
