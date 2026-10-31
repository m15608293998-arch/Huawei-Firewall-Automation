import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from fastapi import HTTPException
from api.admin_users import AdminUserService, ManagedUserValidationError
from api.auth import Principal, require_firewall_ip_allow, require_firewall_ports_allow
from api.schemas import ManagedUserUpdate
from api.storage import JobStorage


class FakeKeycloakAdmin:
    def __init__(self) -> None:
        self.profiles = []

    def get_user(self, subject_id):
        return {"id": subject_id, "username": "employee-a", "enabled": True}

    def set_user_profile(self, subject_id, profile):
        self.profiles.append((subject_id, profile))

    def search_users(self, query, limit):
        return [{"subject_id": "user-subject", "username": query, "enabled": True}]


class AdminUserServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage = JobStorage(Path(self.temp_dir.name) / "users.sqlite3")
        self.keycloak = FakeKeycloakAdmin()
        self.service = AdminUserService(self.storage, self.keycloak)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_human_user_access_is_keyed_by_keycloak_subject(self) -> None:
        result = self.service.update(
            "user-subject",
            ManagedUserUpdate(
                username="employee-a",
                display_name="Employee A",
                profile="user",
                allowed_ips=["192.168.5.224"],
            ),
        )

        self.assertEqual(result["subject_id"], "user-subject")
        self.assertEqual(
            result["permissions"],
            [
                "firewall.ip.allow",
                "firewall.ip.deny",
                "firewall.job.read",
                "firewall.ports.allow",
                "firewall.ports.deny",
                "firewall.snapshot.read",
            ],
        )
        self.assertEqual(
            self.storage.get_subject_allowed_ips("user-subject"),
            [],
        )
        self.assertIn(("user-subject", "user"), self.keycloak.profiles)

    def test_user_cannot_receive_admin_permission(self) -> None:
        with self.assertRaises(ManagedUserValidationError):
            self.service.update(
                "user-subject",
                ManagedUserUpdate(
                    username="employee-a",
                    profile="user",
                    permissions=["identity.user.manage"],
                    allowed_ips=["192.168.5.224"],
                ),
            )

    def test_cli_manage_permissions_grants_user_profile_and_creates_managed_user(self) -> None:
        db_path = Path(self.temp_dir.name) / "users.sqlite3"
        script_path = Path(__file__).resolve().parents[1] / "scripts" / "manage_permissions.py"
        env = {"TRADE_ACCESS_API_DATABASE_PATH": str(db_path)}
        proc = subprocess.run(
            [
                sys.executable,
                str(script_path),
                "grant",
                "--subject-id",
                "cli-user-1",
                "--username",
                "cli-employee",
                "--profile",
                "user",
            ],
            capture_output=True,
            text=True,
            env=env,
            check=True,
        )
        output = json.loads(proc.stdout)
        self.assertEqual(output["subject_id"], "cli-user-1")
        self.assertEqual(output["profile"], "user")
        managed = self.storage.get_managed_user("cli-user-1")
        self.assertIsNotNone(managed)
        self.assertEqual(managed["username"], "cli-employee")
        self.assertTrue(managed["enabled"])
        self.assertEqual(
            managed["permissions"],
            [
                "firewall.ip.allow",
                "firewall.ip.deny",
                "firewall.job.read",
                "firewall.ports.allow",
                "firewall.ports.deny",
                "firewall.snapshot.read",
            ],
        )

    def run_cli(self, *arguments):
        script = Path(__file__).resolve().parents[1] / "scripts/manage_permissions.py"
        result = subprocess.run(
            [sys.executable, str(script), *arguments], capture_output=True, text=True,
            env={"TRADE_ACCESS_API_DATABASE_PATH": str(self.storage.database_path)}, check=True,
        )
        return json.loads(result.stdout)

    def test_cli_profile_revoke_removes_legacy_and_granular_grants(self) -> None:
        for profile in ("user", "admin"):
            with self.subTest(profile=profile):
                subject = "legacy-" + profile
                for permission in ("firewall.allow", "firewall.deny", "firewall.ip.allow", "firewall.job.read"):
                    self.storage.grant_subject_permission(subject, permission, "now")
                result = self.run_cli("revoke", "--subject-id", subject, "--profile", profile)
                self.assertIn("firewall.ip.allow", result["revoked_permissions"])
                self.assertEqual(self.storage.get_subject_permissions(subject), [])
                principal = Principal(subject_id=subject, subject=subject, auth_type="keycloak_bearer")
                with self.assertRaises(HTTPException):
                    require_firewall_ip_allow(principal)

    def test_cli_granular_revoke_expands_legacy_grant_and_preserves_other_access(self) -> None:
        self.storage.grant_subject_permission("legacy", "firewall.allow", "now")
        self.run_cli("revoke", "--subject-id", "legacy", "--permission", "firewall.ip.allow")
        principal = Principal(subject_id="legacy", subject="legacy", auth_type="keycloak_bearer",
                              permissions=self.storage.get_subject_permissions("legacy"))
        self.assertEqual(principal.permissions, ["firewall.ports.allow"])
        with self.assertRaises(HTTPException):
            require_firewall_ip_allow(principal)
        require_firewall_ports_allow(principal)

    def test_cli_grant_normalizes_existing_legacy_permissions(self) -> None:
        self.storage.grant_subject_permission("legacy", "firewall.allow", "now")
        self.run_cli("grant", "--subject-id", "legacy", "--profile", "user")
        user = self.storage.get_managed_user("legacy")
        self.assertNotIn("firewall.allow", user["permissions"])
        self.assertIn("firewall.ip.allow", user["permissions"])
        self.assertIn("firewall.ports.allow", user["permissions"])


if __name__ == "__main__":
    unittest.main()
