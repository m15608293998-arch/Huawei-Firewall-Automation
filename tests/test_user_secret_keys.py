import tempfile
import unittest
from pathlib import Path

from api.storage import JobStorage
from api.user_secret_keys import UserSecretKeyError, UserSecretKeyService


class UserSecretKeyServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage = JobStorage(Path(self.temp_dir.name) / "keys.sqlite3")
        self.service = UserSecretKeyService(self.storage)
        self.save_user()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def save_user(
        self,
        *,
        enabled: bool = True,
        profile: str = "user",
        permissions: list[str] | None = None,
    ) -> None:
        self.storage.save_managed_user_access(
            subject_id="user-subject",
            username="employee-a",
            display_name="Employee A",
            profile=profile,
            enabled=enabled,
            permissions=permissions or ["firewall.allow", "firewall.job.read"],
            allowed_ips=["192.168.5.224"],
            updated_at="2026-06-09T00:00:00+00:00",
        )

    def create_key(self) -> dict:
        return self.service.create(
            subject_id="user-subject",
            created_by="admin-subject",
            label="employee key",
            expires_in_days=365,
        )

    def test_raw_secret_is_returned_once_and_only_hash_is_stored(self) -> None:
        created = self.create_key()
        stored = self.storage.get_user_secret_key(created["key_id"])

        self.assertTrue(created["secret_key"].startswith("sk1."))
        self.assertNotEqual(stored["key_hash"], created["secret_key"])
        listed = self.service.list("user-subject")
        self.assertNotIn("key_hash", listed[0])
        self.assertNotIn("secret_key", listed[0])

    def test_key_uses_current_user_permissions_without_reissue(self) -> None:
        created = self.create_key()
        _, initial_user = self.service.verify(created["secret_key"])
        self.assertEqual(initial_user["permissions"], ["firewall.allow", "firewall.job.read"])

        self.save_user(permissions=["firewall.deny"])
        _, updated_user = self.service.verify(created["secret_key"])
        self.assertEqual(updated_user["permissions"], ["firewall.deny"])

    def test_revoked_key_is_rejected_immediately(self) -> None:
        created = self.create_key()
        self.service.revoke("user-subject", created["key_id"])

        with self.assertRaisesRegex(UserSecretKeyError, "revoked"):
            self.service.verify(created["secret_key"])

    def test_user_can_have_only_one_active_secret_key(self) -> None:
        first = self.create_key()

        with self.assertRaisesRegex(UserSecretKeyError, "already has an active SK"):
            self.create_key()

        self.service.revoke("user-subject", first["key_id"])
        replacement = self.create_key()
        self.assertNotEqual(first["secret_key"], replacement["secret_key"])
        self.assertNotEqual(first["key_id"], replacement["key_id"])

    def test_disabled_user_and_admin_profile_are_rejected(self) -> None:
        created = self.create_key()
        self.save_user(enabled=False)
        with self.assertRaisesRegex(UserSecretKeyError, "disabled"):
            self.service.verify(created["secret_key"])

        self.save_user(profile="admin")
        with self.assertRaisesRegex(UserSecretKeyError, "profile"):
            self.service.verify(created["secret_key"])


if __name__ == "__main__":
    unittest.main()
