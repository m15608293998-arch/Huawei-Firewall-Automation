try:
    import sqlite3
except ModuleNotFoundError:
    import pysqlite3 as sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from api.storage import JobStorage


class StorageMigrationTests(unittest.TestCase):
    def test_legacy_job_schema_receives_keycloak_principal_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "legacy.sqlite3"
            with sqlite3.connect(database_path) as conn:
                conn.execute(
                    """
                    create table jobs (
                        job_id text primary key,
                        status text not null,
                        action text not null,
                        target_ip text not null,
                        mask integer not null,
                        description text,
                        client_request_id text,
                        principal_subject text,
                        auth_type text,
                        runner_status text,
                        runner_rc integer,
                        error_message text,
                        created_at text not null,
                        started_at text,
                        finished_at text,
                        artifact_dir text,
                        local_tmp_dir text,
                        principal_key_id text
                    )
                    """
                )
            storage = JobStorage(database_path)

            with storage._connect() as conn:
                job_columns = {
                    row["name"] for row in conn.execute("pragma table_info(jobs)")
                }

            self.assertIn("principal_id", job_columns)
            self.assertIn("principal_client_id", job_columns)
            self.assertIn("permission_code", job_columns)

    def test_legacy_client_tables_are_not_created_for_new_database(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            storage = JobStorage(Path(temp_dir) / "new.sqlite3")
            with storage._connect() as conn:
                tables = {
                    row["name"]
                    for row in conn.execute(
                        "select name from sqlite_master where type = 'table'"
                    )
                }

            self.assertNotIn("managed_clients", tables)
            self.assertNotIn("client_permissions", tables)
            self.assertNotIn("client_allowed_ips", tables)
            self.assertNotIn("subject_api_keys", tables)
            self.assertNotIn("user_secret_keys", tables)
            self.assertIn("offline_api_keys", tables)
            self.assertIn("offline_api_key_authorizations", tables)

    def test_legacy_admin_permission_is_migrated_to_user_management(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "legacy-permission.sqlite3"
            storage = JobStorage(database_path)
            storage.grant_subject_permission(
                "admin-subject",
                "identity.client.manage",
                "2026-06-09T00:00:00+00:00",
            )
            storage.initialize()

            self.assertEqual(
                storage.get_subject_permissions("admin-subject"),
                ["identity.user.manage"],
            )


class StorageQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temp_dir.name) / "queue.sqlite3"
        self.storage = JobStorage(self.database_path)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def create_job(self, job_id: str, created_at: str) -> None:
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
                "principal_client_id": "client-a",
                "principal_key_id": "key-a",
                "principal_type": "employee",
                "auth_type": "secret_key",
                "permission_code": "firewall.allow",
                "runner_status": None,
                "runner_rc": None,
                "error_message": None,
                "created_at": created_at,
                "started_at": None,
                "finished_at": None,
                "artifact_dir": "/tmp/artifacts/{0}".format(job_id),
                "local_tmp_dir": "/tmp/jobs/{0}".format(job_id),
            }
        )

    def test_claim_uses_fifo_order_and_marks_job_running(self) -> None:
        self.create_job("job-1", "2026-06-05T00:00:00+00:00")
        self.create_job("job-2", "2026-06-05T00:00:01+00:00")

        claimed = self.storage.claim_next_pending_job(
            "2026-06-05T00:01:00+00:00"
        )

        self.assertIsNotNone(claimed)
        self.assertEqual(claimed["job_id"], "job-1")
        self.assertEqual(claimed["status"], "running")
        self.assertEqual(claimed["ports"], [12001])
        self.assertEqual(self.storage.get_job("job-2")["status"], "pending")

    def test_list_jobs_can_filter_by_subject_and_status(self) -> None:
        self.create_job("job-1", "2026-06-05T00:00:00+00:00")
        self.create_job("job-2", "2026-06-05T00:00:01+00:00")
        self.storage.update_job("job-2", {"principal_id": "subject-b"})
        self.storage.update_job("job-1", {"status": "successful"})

        subject_jobs = self.storage.list_jobs(principal_id="subject-a")
        pending_jobs = self.storage.list_jobs(job_status="pending")

        self.assertEqual([job["job_id"] for job in subject_jobs], ["job-1"])
        self.assertEqual([job["job_id"] for job in pending_jobs], ["job-2"])

    def test_list_jobs_can_paginate_with_offset(self) -> None:
        self.create_job("job-1", "2026-06-05T00:00:00+00:00")
        self.create_job("job-2", "2026-06-05T00:00:01+00:00")
        self.create_job("job-3", "2026-06-05T00:00:02+00:00")

        first_page = self.storage.list_jobs(limit=2, offset=0)
        second_page = self.storage.list_jobs(limit=2, offset=2)

        self.assertEqual([job["job_id"] for job in first_page], ["job-3", "job-2"])
        self.assertEqual([job["job_id"] for job in second_page], ["job-1"])

    def test_two_storage_instances_cannot_claim_same_job(self) -> None:
        self.create_job("job-1", "2026-06-05T00:00:00+00:00")
        first_storage = JobStorage(self.database_path)
        second_storage = JobStorage(self.database_path)

        with ThreadPoolExecutor(max_workers=2) as executor:
            claims = list(
                executor.map(
                    lambda storage: storage.claim_next_pending_job(
                        "2026-06-05T00:01:00+00:00"
                    ),
                    [first_storage, second_storage],
                )
            )

        claimed_jobs = [job for job in claims if job is not None]
        self.assertEqual(len(claimed_jobs), 1)
        self.assertEqual(claimed_jobs[0]["job_id"], "job-1")

    def test_managed_user_permissions_are_keyed_by_subject(self) -> None:
        self.storage.save_managed_user_access(
            subject_id="user-subject-a",
            username="employee-a",
            display_name="Employee A",
            profile="user",
            enabled=True,
            permissions=["firewall.allow", "firewall.job.read"],
            allowed_ips=["192.168.5.224"],
            updated_at="2026-06-09T00:00:00+00:00",
        )

        record = self.storage.get_managed_user("user-subject-a")
        self.assertEqual(record["username"], "employee-a")
        self.assertEqual(
            self.storage.get_subject_permissions("user-subject-a"),
            ["firewall.allow", "firewall.job.read"],
        )
        self.assertEqual(record["allowed_ips"], ["192.168.5.224"])


if __name__ == "__main__":
    unittest.main()
