import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

from api.offline_api_keys import (
    OfflineApiKeyConfigurationError,
    OfflineApiKeyError,
    OfflineApiKeyNotFoundError,
    OfflineApiKeyService,
)
from api.storage import JobStorage


class FakeVerifier:
    def __init__(self, subject_id: str = "user-subject") -> None:
        self.subject_id = subject_id

    def verify(self, token: str) -> dict:
        return {
            "sub": self.subject_id,
            "preferred_username": "employee-a",
            "azp": "trade-access-offline",
            "aud": "trade-access-api",
            "exp": int(time.time()) + 300,
            "resource_access": {
                "trade-access-api": {"roles": ["trade-access-user"]},
            },
        }


class FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200) -> None:
        self.payload = payload
        self.status_code = status_code
        self.content = b"json"
        self.is_success = 200 <= status_code < 300

    def json(self) -> dict:
        return self.payload


class OfflineApiKeyServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.storage = JobStorage(Path(self.temp_dir.name) / "keys.sqlite3")
        self.storage.save_managed_user_access(
            subject_id="user-subject",
            username="employee-a",
            display_name="Employee A",
            profile="user",
            enabled=True,
            permissions=["firewall.allow", "firewall.job.read"],
            allowed_ips=["192.168.5.224"],
            updated_at="2026-06-15T00:00:00+00:00",
        )
        self.service = OfflineApiKeyService(
            storage=self.storage,
            token_verifier=FakeVerifier(),
            authorization_url="https://keycloak.example/realms/trade-access/protocol/openid-connect/auth",
            token_url="https://keycloak.example/realms/trade-access/protocol/openid-connect/token",
            client_id="trade-access-offline",
            client_secret="offline-client-secret",
            scope="openid profile offline_access",
            timeout_seconds=5,
            ca_cert=None,
            token_encryption_key="unit-test-offline-token-encryption-key",
        )

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def begin(self) -> tuple[dict, str]:
        result = self.service.begin_authorization(
            subject_id="user-subject",
            label="automation",
            redirect_uri="https://api.example/api/v1/auth/offline/callback",
        )
        query = parse_qs(urlparse(result["authorization_url"]).query)
        return result, query["state"][0]

    def complete(self, state: str) -> dict:
        with patch(
            "api.offline_api_keys.httpx.post",
            return_value=FakeResponse(
                {
                    "access_token": "signed-access-token",
                    "refresh_token": "offline-token-value-with-enough-random-data",
                    "scope": "openid profile offline_access",
                }
            ),
        ):
            return self.service.complete_authorization(state, "authorization-code")

    def test_authorization_uses_one_confidential_client_and_offline_scope(self) -> None:
        result, state = self.begin()
        query = parse_qs(urlparse(result["authorization_url"]).query)

        self.assertTrue(state)
        self.assertEqual(query["client_id"], ["trade-access-offline"])
        self.assertIn("offline_access", query["scope"][0].split())
        self.assertEqual(query["code_challenge_method"], ["S256"])

    def test_created_key_is_sk_plus_offline_token_and_plaintext_is_not_stored(self) -> None:
        _, state = self.begin()
        created = self.complete(state)
        stored = self.storage.get_offline_api_key_by_hash(
            self.service._hash(created["api_key"])
        )

        self.assertEqual(
            created["api_key"],
            "sk-offline-token-value-with-enough-random-data",
        )
        self.assertIsNotNone(stored)
        self.assertNotIn("api_key", stored)
        self.assertNotIn("offline-token-value", str(stored))
        self.assertIn("encrypted_offline_token", stored)
        self.assertNotIn("api_key", self.service.list("user-subject")[0])
        self.assertNotIn("encrypted_offline_token", created)
        self.assertNotIn("offline_token_updated_at", created)

    def test_api_key_refreshes_at_keycloak_and_uses_cached_claims(self) -> None:
        _, state = self.begin()
        created = self.complete(state)
        response = FakeResponse({"access_token": "refreshed-access-token"})

        with patch("api.offline_api_keys.httpx.post", return_value=response) as post:
            record, claims = self.service.authenticate(created["api_key"])
            cached_record, cached_claims = self.service.authenticate(created["api_key"])

        self.assertEqual(record["subject_id"], "user-subject")
        self.assertEqual(claims["sub"], "user-subject")
        self.assertEqual(cached_record["key_id"], record["key_id"])
        self.assertEqual(cached_claims["sub"], "user-subject")
        self.assertEqual(post.call_count, 1)
        self.assertEqual(
            post.call_args.kwargs["data"]["refresh_token"],
            "offline-token-value-with-enough-random-data",
        )

    def test_missing_encryption_key_disables_offline_api_keys(self) -> None:
        service = OfflineApiKeyService(
            storage=self.storage,
            token_verifier=FakeVerifier(),
            authorization_url="https://keycloak.example/realms/trade-access/protocol/openid-connect/auth",
            token_url="https://keycloak.example/realms/trade-access/protocol/openid-connect/token",
            client_id="trade-access-offline",
            client_secret="offline-client-secret",
            scope="openid profile offline_access",
            timeout_seconds=5,
            ca_cert=None,
            token_encryption_key=None,
        )

        self.assertFalse(service.configured)
        with self.assertRaises(OfflineApiKeyConfigurationError):
            service.begin_authorization(
                subject_id="user-subject",
                label="automation",
                redirect_uri="https://api.example/api/v1/auth/offline/callback",
            )

    def test_revoke_rejects_key_immediately(self) -> None:
        _, state = self.begin()
        created = self.complete(state)
        self.service.revoke("user-subject", created["key_id"])

        with self.assertRaisesRegex(OfflineApiKeyError, "revoked"):
            self.service.authenticate(created["api_key"])
        with self.assertRaises(OfflineApiKeyNotFoundError):
            self.service.revoke("user-subject", created["key_id"])

    def test_update_label_only_changes_the_current_users_active_key_name(self) -> None:
        _, state = self.begin()
        created = self.complete(state)
        token_hash = self.service._hash(created["api_key"])
        before = self.storage.get_offline_api_key_by_hash(token_hash)

        updated = self.service.update_label(
            "user-subject",
            created["key_id"],
            "renamed automation",
        )
        after = self.storage.get_offline_api_key_by_hash(token_hash)

        self.assertEqual(updated["label"], "renamed automation")
        self.assertEqual(updated["key_id"], created["key_id"])
        self.assertEqual(after["token_hash"], before["token_hash"])
        self.assertEqual(after["key_hint"], before["key_hint"])
        with self.assertRaises(OfflineApiKeyNotFoundError):
            self.service.update_label(
                "other-subject",
                created["key_id"],
                "not allowed",
            )

        self.service.revoke("user-subject", created["key_id"])
        with self.assertRaises(OfflineApiKeyNotFoundError):
            self.service.update_label(
                "user-subject",
                created["key_id"],
                "too late",
            )

    def test_refresh_response_token_rotates_stored_token_without_changing_api_key(
        self,
    ) -> None:
        _, state = self.begin()
        created = self.complete(state)
        with patch(
            "api.offline_api_keys.httpx.post",
            return_value=FakeResponse(
                {
                    "access_token": "refreshed-access-token",
                    "refresh_token": "rotated-offline-token",
                }
            ),
        ) as first_post:
            record, claims = self.service.authenticate(created["api_key"])
        self.service._claims_cache.clear()
        with patch(
            "api.offline_api_keys.httpx.post",
            return_value=FakeResponse(
                {
                    "access_token": "second-refreshed-access-token",
                    "refresh_token": "second-rotated-offline-token",
                }
            ),
        ) as second_post:
            second_record, second_claims = self.service.authenticate(created["api_key"])

        self.assertEqual(record["key_id"], created["key_id"])
        self.assertEqual(claims["sub"], "user-subject")
        self.assertEqual(second_record["key_id"], created["key_id"])
        self.assertEqual(second_claims["sub"], "user-subject")
        self.assertEqual(len(self.service.list("user-subject")), 1)
        self.assertEqual(
            first_post.call_args.kwargs["data"]["refresh_token"],
            "offline-token-value-with-enough-random-data",
        )
        self.assertEqual(
            second_post.call_args.kwargs["data"]["refresh_token"],
            "rotated-offline-token",
        )

    def test_refresh_retries_with_new_stored_token_after_concurrent_rotation(
        self,
    ) -> None:
        _, state = self.begin()
        created = self.complete(state)
        calls = []

        def post_side_effect(*args, **kwargs):
            refresh_token = kwargs["data"]["refresh_token"]
            calls.append(refresh_token)
            if len(calls) == 1:
                self.storage.update_offline_api_key_token(
                    created["key_id"],
                    self.service._encrypt_offline_token("already-rotated-offline-token"),
                    "2026-06-15T00:02:00+00:00",
                )
                return FakeResponse(
                    {
                        "error": "invalid_grant",
                        "error_description": "Maximum allowed refresh token reuse exceeded",
                    },
                    status_code=400,
                )
            return FakeResponse(
                {
                    "access_token": "refreshed-after-race",
                    "refresh_token": "next-rotated-offline-token",
                }
            )

        with patch("api.offline_api_keys.httpx.post", side_effect=post_side_effect):
            record, claims = self.service.authenticate(created["api_key"])

        self.assertEqual(record["key_id"], created["key_id"])
        self.assertEqual(claims["sub"], "user-subject")
        self.assertEqual(
            calls,
            [
                "offline-token-value-with-enough-random-data",
                "already-rotated-offline-token",
            ],
        )

    def test_disabled_user_cannot_use_api_key(self) -> None:
        _, state = self.begin()
        created = self.complete(state)
        self.storage.save_managed_user_access(
            subject_id="user-subject",
            username="employee-a",
            display_name="Employee A",
            profile="user",
            enabled=False,
            permissions=["firewall.allow"],
            allowed_ips=["192.168.5.224"],
            updated_at="2026-06-15T00:01:00+00:00",
        )

        with self.assertRaisesRegex(OfflineApiKeyError, "disabled"):
            self.service.authenticate(created["api_key"])


if __name__ == "__main__":
    unittest.main()
