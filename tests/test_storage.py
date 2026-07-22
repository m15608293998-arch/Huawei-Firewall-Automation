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
                tables = {
                    row["name"]
                    for row in conn.execute(
                        "select name from sqlite_master where type = 'table'"
                    )
                }

            self.assertIn("principal_id", job_columns)
            self.assertIn("principal_client_id", job_columns)
            self.assertIn("permission_code", job_columns)
            self.assertIn("firewall_targets", job_columns)
            self.assertIn("desired_state", job_columns)
            self.assertIn("state_version", job_columns)
            self.assertIn("next_attempt_at", job_columns)
            self.assertIn("job_firewall_targets", tables)
            self.assertIn("desired_access_states", tables)

    def test_legacy_offline_api_key_schema_receives_rotating_token_columns(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "legacy-offline-keys.sqlite3"
            with sqlite3.connect(database_path) as conn:
                conn.execute(
                    """
                    create table offline_api_keys (
                        key_id text primary key,
                        subject_id text not null,
                        label text not null,
                        token_hash text not null unique,
                        key_hint text not null,
                        created_at text not null,
                        last_used_at text,
                        revoked_at text
                    )
                    """
                )
            storage = JobStorage(database_path)

            with storage._connect() as conn:
                columns = {
                    row["name"]
                    for row in conn.execute(
                        "pragma table_info(offline_api_keys)"
                    ).fetchall()
                }

            self.assertIn("encrypted_offline_token", columns)
            self.assertIn("offline_token_updated_at", columns)

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

    def create_job(
        self,
        job_id: str,
        created_at: str,
        target_ip: str = "192.168.5.224",
    ) -> None:
        self.storage.create_job(
            {
                "job_id": job_id,
                "status": "pending",
                "action": "allow",
                "target_ip": target_ip,
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

    def test_job_reads_can_include_parent_and_child_snapshot(self) -> None:
        self.create_job("job-1", "2026-06-05T00:00:00+00:00")
        self.storage.ensure_job_targets(
            "job-1",
            ("PG-FW", "IDC-FW"),
            "/tmp/jobs/job-1",
        )
        self.storage.update_job_target(
            "job-1",
            "PG-FW",
            {"status": "verifying", "attempt_count": 1},
        )

        detail = self.storage.get_job("job-1", include_targets=True)
        listed = self.storage.list_jobs(include_targets=True)[0]

        self.assertEqual(
            [target["firewall_code"] for target in detail["target_results"]],
            ["IDC-FW", "PG-FW"],
        )
        self.assertEqual(
            [target["firewall_code"] for target in listed["target_results"]],
            ["IDC-FW", "PG-FW"],
        )

    def test_parent_advances_to_verifying_only_when_all_children_are_ready(self) -> None:
        self.create_job("job-1", "2026-06-05T00:00:00+00:00")
        self.storage.ensure_job_targets(
            "job-1",
            ("PG-FW", "IDC-FW"),
            "/tmp/jobs/job-1",
        )
        self.storage.update_job("job-1", {"status": "applying"})
        self.storage.update_job_target(
            "job-1",
            "PG-FW",
            {
                "status": "verifying",
                "runner_status": "failed",
                "runner_rc": 2,
                "error_message": "old failure",
                "finished_at": "2026-06-05T00:00:30+00:00",
            },
        )

        self.assertFalse(self.storage.mark_job_verifying_if_targets_ready("job-1"))
        self.assertEqual(self.storage.get_job("job-1")["status"], "applying")

        self.storage.update_job_target("job-1", "IDC-FW", {"status": "verified"})
        self.assertTrue(self.storage.mark_job_verifying_if_targets_ready("job-1"))
        parent = self.storage.get_job("job-1")
        self.assertEqual(parent["status"], "verifying")
        self.assertEqual(parent["runner_status"], "verifying")

    def test_start_target_attempt_updates_parent_and_child_together(self) -> None:
        self.create_job("job-1", "2026-06-05T00:00:00+00:00")
        self.storage.ensure_job_targets("job-1", ("PG-FW",), "/tmp/jobs/job-1")
        self.storage.update_job(
            "job-1",
            {"status": "verifying", "runner_status": "verifying"},
        )
        self.storage.update_job_target("job-1", "PG-FW", {"status": "verifying"})

        self.storage.start_job_target_attempt(
            "job-1",
            "PG-FW",
            "reconciling",
            2,
            "2026-06-05T00:01:00+00:00",
        )

        job = self.storage.get_job("job-1", include_targets=True)
        self.assertEqual(job["status"], "applying")
        self.assertEqual(job["runner_status"], "applying")
        self.assertEqual(job["target_results"][0]["status"], "reconciling")
        self.assertEqual(job["target_results"][0]["attempt_count"], 2)
        self.assertIsNone(job["target_results"][0]["runner_status"])
        self.assertIsNone(job["target_results"][0]["runner_rc"])
        self.assertIsNone(job["target_results"][0]["error_message"])
        self.assertIsNone(job["target_results"][0]["finished_at"])

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

    def test_reconciling_job_wait_does_not_block_other_ip_but_blocks_same_ip(self) -> None:
        self.create_job("job-retry", "2026-06-05T00:00:00+00:00")
        self.storage.update_job(
            "job-retry",
            {
                "status": "reconciling",
                "next_attempt_at": "2026-06-05T00:02:00+00:00",
            },
        )
        self.create_job("job-same-ip", "2026-06-05T00:00:01+00:00")
        self.create_job(
            "job-other-ip",
            "2026-06-05T00:00:02+00:00",
            target_ip="192.168.5.225",
        )

        claimed = self.storage.claim_next_runnable_job(
            "2026-06-05T00:01:00+00:00"
        )

        self.assertIsNotNone(claimed)
        self.assertEqual(claimed["job_id"], "job-other-ip")
        self.storage.update_job(
            "job-other-ip",
            {
                "status": "successful",
                "finished_at": "2026-06-05T00:01:10+00:00",
            },
        )
        self.assertIsNone(
            self.storage.claim_next_runnable_job("2026-06-05T00:01:30+00:00")
        )

        retry = self.storage.claim_next_runnable_job(
            "2026-06-05T00:02:00+00:00"
        )
        self.assertIsNotNone(retry)
        self.assertEqual(retry["job_id"], "job-retry")

    def test_parent_children_and_desired_state_round_trip(self) -> None:
        targets = ["PG-FW", "PG-FW-1", "IDC-FW"]
        self.storage.create_job(
            {
                "job_id": "multi-job",
                "status": "pending",
                "action": "allow",
                "target_ip": "192.168.5.224",
                "mask": 32,
                "ports": [12001],
                "created_at": "2026-07-21T00:00:00+00:00",
                "local_tmp_dir": "/tmp/jobs/multi-job",
                "firewall_targets": targets,
            },
            targets,
        )

        self.storage.update_job_target(
            "multi-job",
            "PG-FW",
            {
                "status": "verified",
                "attempt_count": 1,
                "before_state": {"ip_present": False, "ports": []},
                "desired_state": {"ip_present": True, "ports": [12001], "version": 1},
                "observed_state": {"ip_present": True, "ports": [12001]},
            },
        )
        first = self.storage.save_desired_access_state(
            target_ip="192.168.5.224",
            ip_present=True,
            ports=[12002, 12001, 12001],
            source_job_id="multi-job",
            updated_at="2026-07-21T00:01:00+00:00",
        )
        second = self.storage.save_desired_access_state(
            target_ip="192.168.5.224",
            ip_present=True,
            ports=[12001],
            source_job_id="multi-job-2",
            updated_at="2026-07-21T00:02:00+00:00",
        )

        job = self.storage.get_job("multi-job")
        children = self.storage.list_job_targets("multi-job")
        desired = self.storage.get_desired_access_state("192.168.5.224")
        self.assertEqual(job["firewall_targets"], targets)
        self.assertEqual(
            [child["firewall_code"] for child in children],
            ["IDC-FW", "PG-FW", "PG-FW-1"],
        )
        self.assertEqual(
            self.storage.get_job_target("multi-job", "PG-FW")["observed_state"],
            {"ip_present": True, "ports": [12001]},
        )
        self.assertEqual(first["ports"], [12001, 12002])
        self.assertEqual(first["version"], 1)
        self.assertEqual(second["version"], 2)
        self.assertEqual(desired["ports"], [12001])
        self.assertEqual(desired["version"], 2)

    def test_legacy_job_can_backfill_firewall_child_rows(self) -> None:
        self.create_job("legacy-job", "2026-06-05T00:00:00+00:00")

        self.storage.ensure_job_targets(
            "legacy-job",
            ("PG-FW", "PG-FW-1", "IDC-FW"),
            "/tmp/jobs/legacy-job",
        )

        job = self.storage.get_job("legacy-job")
        children = self.storage.list_job_targets("legacy-job")
        self.assertEqual(job["firewall_targets"], ["PG-FW", "PG-FW-1", "IDC-FW"])
        self.assertEqual(
            [child["firewall_code"] for child in children],
            ["IDC-FW", "PG-FW", "PG-FW-1"],
        )

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
