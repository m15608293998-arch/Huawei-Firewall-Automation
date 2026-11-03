from contextlib import contextmanager, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from api.storage import JobStorage


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "manage_permissions.py"
SPEC = importlib.util.spec_from_file_location("permission_concurrency_cli", SCRIPT)
CLI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLI)


class PermissionConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name) / "users.sqlite3"
        self.storage = JobStorage(path)
        self.other = JobStorage(path)
        self.storage.save_managed_user_access(
            subject_id="subject", username="employee", display_name="Original",
            profile="user", enabled=True,
            permissions=["firewall.ip.allow", "firewall.ports.allow"],
            allowed_ips=["203.0.113.1", "203.0.113.2"], updated_at="before",
        )

    def run_cli(self, *arguments, storage=None):
        output = io.StringIO()
        with patch.object(CLI, "JobStorage", return_value=storage or self.storage), \
                patch.object(sys, "argv", [str(SCRIPT), *arguments]), redirect_stdout(output):
            self.assertEqual(CLI.main(), 0)
        return json.loads(output.getvalue())

    @contextmanager
    def before_first_write(self, action):
        original_connect = self.storage._connect
        called = []

        class Connection:
            def __init__(self, connection):
                self.connection = connection

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def execute(self, sql, *args):
                if not called and sql.lstrip().lower().startswith(("begin immediate", "insert", "update", "delete")):
                    called.append(True)
                    action()
                return self.connection.execute(sql, *args)

        @contextmanager
        def connect(*args, **kwargs):
            with original_connect(*args, **kwargs) as connection:
                yield Connection(connection)

        with patch.object(self.storage, "_connect", connect):
            yield
        self.assertEqual(called, [True], "The concurrent operation must actually run")

    def test_grant_does_not_restore_a_concurrently_revoked_permission(self):
        def revoke():
            self.assertEqual(self.other.revoke_subject_permissions("subject", ["firewall.ip.allow"]),
                             ["firewall.ip.allow"])
            self.assertNotIn("firewall.ip.allow", self.other.get_subject_permissions("subject"))

        with self.before_first_write(revoke):
            self.run_cli("grant", "--subject-id", "subject", "--permission", "firewall.job.read")
        self.assertEqual(self.storage.get_subject_permissions("subject"),
                         ["firewall.job.read", "firewall.ports.allow"])

    def test_grant_does_not_restore_a_concurrently_revoked_ip(self):
        def revoke():
            self.assertTrue(self.other.revoke_subject_allowed_ip("subject", "203.0.113.1"))

        with self.before_first_write(revoke):
            self.run_cli("grant", "--subject-id", "subject", "--ip", "203.0.113.3")
        self.assertEqual(self.storage.get_subject_allowed_ips("subject"), ["203.0.113.2", "203.0.113.3"])

    def test_grant_preserves_a_concurrent_disable_and_profile_update(self):
        def disable():
            self.other.save_managed_user_access(
                subject_id="subject", username="renamed", display_name="Changed by admin",
                profile="admin", enabled=False,
                permissions=["firewall.ip.allow", "firewall.ports.allow"],
                allowed_ips=["203.0.113.1", "203.0.113.2"], updated_at="disabled",
            )

        with self.before_first_write(disable):
            output = self.run_cli("grant", "--subject-id", "subject", "--permission", "firewall.job.read")
        record = self.storage.get_managed_user("subject")
        self.assertFalse(record["enabled"])
        self.assertEqual(record["username"], "renamed")
        self.assertEqual(record["display_name"], "Changed by admin")
        self.assertEqual(record["profile"], "admin")
        self.assertFalse(output["enabled"])
        self.assertEqual(output["username"], "renamed")
        self.assertEqual(output["profile"], "admin")

    def test_overlapping_grants_keep_both_permissions_and_ip_ranges(self):
        def another_grant():
            self.run_cli("grant", "--subject-id", "subject", "--permission", "firewall.snapshot.read",
                         "--ip", "203.0.113.3", storage=self.other)

        with self.before_first_write(another_grant):
            self.run_cli("grant", "--subject-id", "subject", "--permission", "firewall.job.read",
                         "--ip", "203.0.113.4")
        self.assertEqual(self.storage.get_subject_permissions("subject"),
                         ["firewall.ip.allow", "firewall.job.read", "firewall.ports.allow", "firewall.snapshot.read"])
        self.assertEqual(self.storage.get_subject_allowed_ips("subject"),
                         ["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"])

    def test_grant_rolls_back_user_metadata_if_access_write_fails(self):
        before = self.storage.get_managed_user("subject")
        with patch.object(self.storage, "_replace_subject_access", side_effect=RuntimeError("injected write failure")):
            with self.assertRaisesRegex(RuntimeError, "injected write failure"):
                self.run_cli("grant", "--subject-id", "subject", "--username", "replacement",
                             "--permission", "firewall.job.read", "--ip", "203.0.113.3")
        self.assertEqual(self.storage.get_managed_user("subject"), before)

    def test_explicit_enable_and_disable_still_override_existing_status(self):
        for flag, expected in (("--disabled", False), ("--enabled", True)):
            with self.subTest(flag=flag):
                output = self.run_cli("grant", "--subject-id", "subject", flag,
                                      "--permission", "firewall.job.read")
                self.assertEqual(output["enabled"], expected)
                self.assertEqual(self.storage.get_managed_user("subject")["enabled"], expected)


if __name__ == "__main__":
    unittest.main()
