import tempfile
import unittest
from pathlib import Path

from api.admin_users import AdminUserService, ManagedUserValidationError
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
            ["firewall.allow", "firewall.deny", "firewall.job.read"],
        )
        self.assertEqual(
            self.storage.get_subject_allowed_ips("user-subject"),
            ["192.168.5.224"],
        )
        self.assertIn(("user-subject", "user"), self.keycloak.profiles)

    def test_user_requires_ip_and_cannot_receive_admin_permission(self) -> None:
        with self.assertRaises(ManagedUserValidationError):
            self.service.update(
                "user-subject",
                ManagedUserUpdate(
                    username="employee-a",
                    profile="user",
                    allowed_ips=[],
                ),
            )

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


if __name__ == "__main__":
    unittest.main()
