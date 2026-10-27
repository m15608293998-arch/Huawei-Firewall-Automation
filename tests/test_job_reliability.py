import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from api import storage as storage_module
from api.storage import JobStorage


def make_job(job_id, request_id="request-1", principal_id="user-a", ports=None):
    return {
        "job_id": job_id, "status": "pending", "action": "allow",
        "target_ip": "203.0.113.10", "mask": 32,
        "ports": [443] if ports is None else ports,
        "client_request_id": request_id, "principal_id": principal_id,
        "created_at": "2026-10-27T00:00:00+00:00",
        "local_tmp_dir": "/tmp/fixture-" + job_id,
        "firewall_targets": ["A", "B", "C"],
    }


class QueueReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "jobs.sqlite3"
        self.storage = JobStorage(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_same_request_is_returned_after_later_deny_without_reenqueue(self):
        self.storage.create_job(make_job("first"))
        self.storage.update_job("first", {"status": "successful"})
        deny = {**make_job("deny", "request-2"), "action": "deny", "ports": []}
        self.storage.create_job(deny)
        self.storage.update_job("deny", {"status": "successful"})
        repeated = self.storage.create_job(make_job("retry"))
        self.assertEqual(repeated["job_id"], "first")
        self.assertEqual(repeated["status"], "successful")
        self.assertEqual(len(self.storage.list_jobs()), 2)

    def test_request_key_conflict_is_rejected_without_new_children(self):
        self.storage.create_job(make_job("first"))
        with self.assertRaises(storage_module.IdempotencyConflictError):
            self.storage.create_job(make_job("conflict", ports=[80]))
        self.assertIsNone(self.storage.get_job("conflict"))
        self.assertEqual(self.storage.list_job_targets("conflict"), [])

    def test_two_storage_instances_accept_one_request_atomically(self):
        other = JobStorage(self.path)
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(store.create_job, make_job(str(index)))
                       for index, store in enumerate((self.storage, other))]
            jobs = [future.result() for future in futures]
        self.assertEqual(jobs[0]["job_id"], jobs[1]["job_id"])
        self.assertEqual(len(self.storage.list_jobs()), 1)
        self.assertEqual(len(self.storage.list_job_targets(jobs[0]["job_id"])), 3)

    def test_concurrent_database_initialization_serializes_schema_changes(self):
        path = Path(self.temp.name) / "concurrent.sqlite3"
        with ThreadPoolExecutor(max_workers=2) as pool:
            initialized = list(pool.map(JobStorage, [path, path]))
        for storage in initialized:
            with storage._connect() as conn:
                columns = {row["name"] for row in conn.execute("pragma table_info(jobs)")}
            self.assertTrue({"deadline_at", "precheck_attempt_count", "request_fingerprint"}.issubset(columns))

    def test_keys_are_scoped_to_subject_and_optional(self):
        for job in (make_job("a"), make_job("b", principal_id="user-b"),
                    make_job("c", request_id=None), make_job("d", request_id=None)):
            self.storage.create_job(job)
        self.assertEqual(len(self.storage.list_jobs()), 4)

    def test_legacy_duplicates_do_not_break_migration_and_are_not_reenqueued(self):
        for index in range(2):
            job_id = str(index)
            self.storage.create_job(make_job(job_id, request_id=None))
            self.storage.update_job(job_id, {"client_request_id": "legacy"})
        JobStorage(self.path)
        with self.assertRaises(storage_module.IdempotencyConflictError):
            self.storage.create_job(make_job("retry", request_id="legacy"))
        self.assertEqual(len(self.storage.list_jobs()), 2)

    def test_single_legacy_request_can_be_reused(self):
        self.storage.create_job(make_job("old", request_id=None))
        self.storage.update_job("old", {"client_request_id": "legacy"})
        self.assertEqual(self.storage.create_job(make_job("new", request_id="legacy"))["job_id"], "old")

    def test_reordered_duplicate_ports_do_not_change_request_identity(self):
        self.storage.create_job(make_job("first", ports=[443, 80, 443]))
        result = self.storage.create_job(make_job("retry", ports=[80, 443]))
        self.assertEqual(result["job_id"], "first")

    def test_deadline_is_persisted_across_reclaims(self):
        self.storage.create_job(make_job("first"))
        first = self.storage.claim_next_runnable_job("2026-10-27T00:00:00+00:00", job_timeout_seconds=60)
        second = self.storage.claim_next_runnable_job("2026-10-27T00:00:30+00:00", job_timeout_seconds=60)
        self.assertEqual(first["deadline_at"], "2026-10-27T00:01:00+00:00")
        self.assertEqual(second["deadline_at"], first["deadline_at"])

    def test_cancel_before_application_cannot_be_resurrected_by_late_precheck(self):
        self.storage.create_job(make_job("first"))
        self.storage.claim_next_runnable_job("2026-10-27T00:00:00+00:00")
        self.storage.start_job_precheck("first")
        self.assertTrue(self.storage.cancel_job("first", "2026-10-27T00:00:01+00:00"))
        self.storage.update_job("first", {"status": "reconciling"})
        self.storage.update_job_target("first", "A", {"status": "prechecked"})
        self.assertFalse(self.storage.begin_job_application("first"))
        self.assertEqual(self.storage.get_job("first")["status"], "canceled")
        self.assertEqual({target["status"] for target in self.storage.list_job_targets("first")}, {"canceled"})

    def test_cancel_is_refused_once_application_is_reserved(self):
        self.storage.create_job(make_job("first"))
        self.storage.claim_next_runnable_job("2026-10-27T00:00:00+00:00")
        self.assertTrue(self.storage.begin_job_application("first"))
        self.assertFalse(self.storage.cancel_job("first", "2026-10-27T00:00:01+00:00"))

    def test_legacy_ledger_commit_prevents_unsafe_cancellation(self):
        self.storage.create_job(make_job("first"))
        self.storage.update_job("first", {"status": "prechecking"})
        self.storage.save_desired_access_state("203.0.113.10", True, [443], "first", "2026-10-27T00:00:00+00:00")
        self.assertFalse(self.storage.cancel_job("first", "2026-10-27T00:00:01+00:00"))

    def test_cancel_and_application_reservation_have_exactly_one_winner(self):
        self.storage.create_job(make_job("first"))
        self.storage.update_job("first", {"status": "prechecking"})
        other = JobStorage(self.path)
        with ThreadPoolExecutor(max_workers=2) as pool:
            cancel = pool.submit(self.storage.cancel_job, "first", "2026-10-27T00:00:01+00:00")
            reserve = pool.submit(other.begin_job_application, "first")
            self.assertEqual(int(cancel.result()) + int(reserve.result()), 1)


if __name__ == "__main__":
    unittest.main()
