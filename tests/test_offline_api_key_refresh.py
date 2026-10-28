import multiprocessing
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import httpx

from api.execution import exclusive_file_lock
from api.keycloak import InvalidAccessTokenError, KeycloakUnavailableError
from api.offline_api_keys import (
    OfflineApiKeyError,
    OfflineApiKeyService,
    OfflineApiKeyUnavailableError,
)
from api.storage import JobStorage
from test_offline_api_keys import FakeResponse, FakeVerifier


def make_service(storage):
    return OfflineApiKeyService(
        storage=storage, token_verifier=FakeVerifier(),
        authorization_url="https://keycloak.example/auth",
        token_url="https://keycloak.example/token", client_id="trade-access-offline",
        client_secret="test-secret", scope="openid offline_access",
        timeout_seconds=2, ca_cert=None, token_encryption_key="refresh-test-encryption-key",
    )


def authenticate_in_process(database_path, raw_key, started, release, calls, results, ready=None):
    service = make_service(JobStorage(Path(database_path)))

    def post(*args, **kwargs):
        with calls.get_lock():
            calls.value += 1
        started.set()
        if not release.wait(5):
            raise AssertionError("Process refresh fixture was not released")
        return FakeResponse({"access_token": "process-access", "refresh_token": "process-rotated-token"})

    try:
        with patch("api.offline_api_keys.httpx.post", side_effect=post):
            if ready is not None:
                ready.set()
            results.put(("ok", service.authenticate(raw_key)[1]["sub"]))
    except Exception as exc:
        results.put(("error", type(exc).__name__))


def hold_key_lock_in_process(lock_path, entered, release):
    with exclusive_file_lock(Path(lock_path), 2):
        entered.set()
        release.wait(10)


class OfflineApiKeyRefreshTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.storage = JobStorage(Path(self.temp.name) / "keys.sqlite3")
        self.storage.save_managed_user_access(
            subject_id="user-subject", username="employee-a", display_name=None,
            profile="user", enabled=True, permissions=[], allowed_ips=[],
            updated_at="2026-10-28T00:00:00+00:00",
        )
        self.service = make_service(self.storage)
        self.raw_key = self.create_key("key-a")

    def create_key(self, key_id):
        token = key_id + "-offline-token-with-enough-random-data"
        raw_key = "sk-" + token
        self.storage.create_offline_api_key({
            "key_id": key_id, "subject_id": "user-subject", "label": key_id,
            "token_hash": self.service._hash(raw_key), "key_hint": "sk-...test",
            "encrypted_offline_token": self.service._encrypt_offline_token(token),
            "offline_token_updated_at": "2026-10-28T00:00:00+00:00",
            "created_at": "2026-10-28T00:00:00+00:00",
            "last_used_at": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
        })
        return raw_key

    def blocked_post(self, entered, release, failure=False):
        def post(*args, **kwargs):
            entered.set()
            if not release.wait(3):
                raise AssertionError("Refresh fixture was not released")
            if failure:
                raise httpx.ConnectError("Local Keycloak outage")
            return FakeResponse({"access_token": "refreshed-access", "refresh_token": "rotated-token"})
        return post

    def test_cached_other_key_does_not_wait_for_slow_refresh(self):
        other_key = self.create_key("key-b")
        with patch("api.offline_api_keys.httpx.post", return_value=FakeResponse({"access_token": "warm"})):
            self.service.authenticate(other_key)
        entered, release = threading.Event(), threading.Event()
        with patch("api.offline_api_keys.httpx.post", side_effect=self.blocked_post(entered, release)) as post, \
                ThreadPoolExecutor(max_workers=2) as pool:
            slow = pool.submit(self.service.authenticate, self.raw_key)
            try:
                self.assertTrue(entered.wait(1))
                fast = pool.submit(self.service.authenticate, other_key)
                self.assertEqual(fast.result(timeout=0.3)[0]["key_id"], "key-b")
                self.assertFalse(slow.done())
            finally:
                release.set()
            slow.result(timeout=2)
        self.assertEqual(post.call_count, 1)

    def test_different_keys_can_refresh_concurrently(self):
        other_key = self.create_key("key-b")
        entered, release = threading.Event(), threading.Event()

        def post(*args, **kwargs):
            if kwargs["data"]["refresh_token"].startswith("key-a"):
                return self.blocked_post(entered, release)(*args, **kwargs)
            return FakeResponse({"access_token": "other-access"})

        with patch("api.offline_api_keys.httpx.post", side_effect=post), ThreadPoolExecutor(max_workers=2) as pool:
            slow = pool.submit(self.service.authenticate, self.raw_key)
            try:
                self.assertTrue(entered.wait(1))
                fast = pool.submit(self.service.authenticate, other_key)
                self.assertEqual(fast.result(timeout=0.3)[0]["key_id"], "key-b")
            finally:
                release.set()
            slow.result(timeout=2)

    def test_same_key_requests_share_one_successful_refresh(self):
        entered, release = threading.Event(), threading.Event()
        with patch("api.offline_api_keys.httpx.post", side_effect=self.blocked_post(entered, release)) as post, \
                ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(self.service.authenticate, self.raw_key) for _ in range(8)]
            try:
                self.assertTrue(entered.wait(1))
            finally:
                release.set()
            for future in futures:
                self.assertEqual(future.result(timeout=2)[0]["key_id"], "key-a")
        self.assertEqual(post.call_count, 1)

    def test_concurrent_failure_is_shared_and_next_request_can_recover(self):
        entered, release, waiting = threading.Event(), threading.Event(), threading.Event()
        with patch("api.offline_api_keys.httpx.post", side_effect=self.blocked_post(entered, release, failure=True)) as post, \
                ThreadPoolExecutor(max_workers=8) as pool:
            leader = pool.submit(self.service.authenticate, self.raw_key)
            try:
                self.assertTrue(entered.wait(1))
                refresh = self.service._refreshes["key-a"]
                original_result = refresh.result
                count, count_lock = 0, threading.Lock()

                def await_refresh(*args, **kwargs):
                    nonlocal count
                    with count_lock:
                        count += 1
                        if count == 7:
                            waiting.set()
                    return original_result(*args, **kwargs)

                with patch.object(refresh, "result", side_effect=await_refresh):
                    followers = [pool.submit(self.service.authenticate, self.raw_key) for _ in range(7)]
                    self.assertTrue(waiting.wait(1))
                    release.set()
                    for future in [leader, *followers]:
                        with self.assertRaises(OfflineApiKeyUnavailableError):
                            future.result(timeout=2)
            finally:
                release.set()
        self.assertEqual(post.call_count, 1)
        with patch("api.offline_api_keys.httpx.post", return_value=FakeResponse({"access_token": "recovered"})):
            self.assertEqual(self.service.authenticate(self.raw_key)[0]["key_id"], "key-a")

    def test_waiter_timeout_does_not_cancel_the_shared_refresh(self):
        entered, release = threading.Event(), threading.Event()
        self.service.timeout_seconds = 0.05
        with patch("api.offline_api_keys.httpx.post", side_effect=self.blocked_post(entered, release)) as post, \
                ThreadPoolExecutor(max_workers=1) as pool:
            leader = pool.submit(self.service.authenticate, self.raw_key)
            try:
                self.assertTrue(entered.wait(1))
                with self.assertRaisesRegex(OfflineApiKeyUnavailableError, "waiting"):
                    self.service.authenticate(self.raw_key)
                self.assertFalse(leader.done())
            finally:
                release.set()
            leader.result(timeout=2)
            self.service.authenticate(self.raw_key)
        self.assertEqual(post.call_count, 1)

    def test_revoke_during_refresh_does_not_wait_and_prevents_authentication(self):
        entered, release = threading.Event(), threading.Event()
        with patch("api.offline_api_keys.httpx.post", side_effect=self.blocked_post(entered, release)), \
                ThreadPoolExecutor(max_workers=2) as pool:
            leader = pool.submit(self.service.authenticate, self.raw_key)
            try:
                self.assertTrue(entered.wait(1))
                revoked = pool.submit(self.service.revoke, "user-subject", "key-a")
                revoked.result(timeout=0.3)
            finally:
                release.set()
            with self.assertRaisesRegex(OfflineApiKeyError, "revoked"):
                leader.result(timeout=2)

    def test_rotation_is_saved_even_when_jwt_verification_is_temporarily_unavailable(self):
        with patch("api.offline_api_keys.httpx.post", return_value=FakeResponse({
            "access_token": "first-access", "refresh_token": "rotated-before-jwks-failure",
        })), patch.object(self.service.token_verifier, "verify", side_effect=KeycloakUnavailableError("JWKS outage")):
            with self.assertRaises(OfflineApiKeyUnavailableError):
                self.service.authenticate(self.raw_key)
        with patch("api.offline_api_keys.httpx.post", return_value=FakeResponse({"access_token": "recovered"})) as post:
            self.assertEqual(self.service.authenticate(self.raw_key)[1]["sub"], "user-subject")
        self.assertEqual(post.call_args.kwargs["data"]["refresh_token"], "rotated-before-jwks-failure")

    def test_expired_caches_are_not_used_when_keycloak_is_unavailable(self):
        with patch("api.offline_api_keys.httpx.post", return_value=FakeResponse({"access_token": "warm"})):
            self.service.authenticate(self.raw_key)
        with patch("api.offline_api_keys.time.time", return_value=time.time() + 301), \
                patch("api.offline_api_keys.httpx.post", side_effect=httpx.ConnectError("Local outage")):
            with self.assertRaises(OfflineApiKeyUnavailableError):
                self.service.authenticate(self.raw_key)

    def test_failed_rotation_write_does_not_publish_success_or_cache(self):
        with patch("api.offline_api_keys.httpx.post", return_value=FakeResponse({
            "access_token": "new-access", "refresh_token": "rotated-but-not-persisted",
        })), patch.object(self.storage, "update_offline_api_key_token", side_effect=OSError("Local write failure")):
            with self.assertRaises(OfflineApiKeyUnavailableError):
                self.service.authenticate(self.raw_key)
        self.assertNotIn("key-a", self.service._claims_cache)
        self.assertNotIn("key-a", self.service._refreshes)
        stored = self.storage.get_offline_api_key_by_hash(self.service._hash(self.raw_key))
        self.assertIsNone(stored["encrypted_access_token"])

    def test_stale_refresh_cannot_overwrite_a_new_token_version(self):
        def post(*args, **kwargs):
            self.storage.update_offline_api_key_token(
                "key-a", self.service._encrypt_offline_token("newer-stored-token"), "2026-10-28T01:00:00+00:00",
            )
            return FakeResponse({"access_token": "stale-access", "refresh_token": "stale-rotation"})

        with patch("api.offline_api_keys.httpx.post", side_effect=post):
            with self.assertRaisesRegex(OfflineApiKeyUnavailableError, "changed"):
                self.service.authenticate(self.raw_key)
        stored = self.storage.get_offline_api_key_by_hash(self.service._hash(self.raw_key))
        self.assertEqual(self.service._offline_token_for_record(stored, ""), "newer-stored-token")
        self.assertNotIn("key-a", self.service._claims_cache)

    def test_shared_cache_is_encrypted_hidden_and_still_verified(self):
        with patch("api.offline_api_keys.httpx.post", return_value=FakeResponse({"access_token": "private-access-token"})):
            public, _ = self.service.authenticate(self.raw_key)
        stored = self.storage.get_offline_api_key_by_hash(self.service._hash(self.raw_key))
        self.assertNotIn("private-access-token", str(stored))
        self.assertNotIn("encrypted_access_token", public)
        self.assertNotIn("access_token_usable_until", public)
        self.assertNotIn("encrypted_access_token", self.service.list("user-subject")[0])
        other = make_service(JobStorage(self.storage.database_path))
        with patch("api.offline_api_keys.httpx.post") as post, \
                patch.object(other.token_verifier, "verify", wraps=other.token_verifier.verify) as verify:
            self.assertEqual(other.authenticate(self.raw_key)[1]["sub"], "user-subject")
        post.assert_not_called()
        verify.assert_called_once_with("private-access-token")

    def test_rejected_shared_access_token_is_replaced_by_a_fresh_keycloak_token(self):
        with patch("api.offline_api_keys.httpx.post", return_value=FakeResponse({"access_token": "old-access"})):
            self.service.authenticate(self.raw_key)
        other = make_service(JobStorage(self.storage.database_path))

        def verify(token):
            if token == "old-access":
                raise InvalidAccessTokenError("Signing key was retired")
            return FakeVerifier().verify(token)

        with patch.object(other.token_verifier, "verify", side_effect=verify), \
                patch("api.offline_api_keys.httpx.post", return_value=FakeResponse({"access_token": "new-access"})) as post:
            self.assertEqual(other.authenticate(self.raw_key)[1]["sub"], "user-subject")
        self.assertEqual(post.call_count, 1)

    def test_access_cache_write_failure_retains_the_rotated_refresh_token(self):
        with patch("api.offline_api_keys.httpx.post", return_value=FakeResponse({
            "access_token": "first-access", "refresh_token": "rotation-before-cache-write-failure",
        })), patch.object(self.storage, "cache_offline_api_key_access_token", side_effect=OSError("Local write failure")):
            with self.assertRaises(OfflineApiKeyUnavailableError):
                self.service.authenticate(self.raw_key)
        with patch("api.offline_api_keys.httpx.post", return_value=FakeResponse({"access_token": "recovered"})) as post:
            self.service.authenticate(self.raw_key)
        self.assertEqual(post.call_args.kwargs["data"]["refresh_token"], "rotation-before-cache-write-failure")

    def test_disabled_user_is_rechecked_when_slow_refresh_completes(self):
        entered, release = threading.Event(), threading.Event()
        with patch("api.offline_api_keys.httpx.post", side_effect=self.blocked_post(entered, release)), \
                ThreadPoolExecutor(max_workers=1) as pool:
            leader = pool.submit(self.service.authenticate, self.raw_key)
            try:
                self.assertTrue(entered.wait(1))
                self.storage.save_managed_user_access(
                    subject_id="user-subject", username="employee-a", display_name=None,
                    profile="user", enabled=False, permissions=[], allowed_ips=[],
                    updated_at="2026-10-28T01:00:00+00:00",
                )
            finally:
                release.set()
            with self.assertRaisesRegex(OfflineApiKeyError, "disabled"):
                leader.result(timeout=2)

    def test_separate_processes_share_refresh_and_encrypted_access_cache(self):
        context = multiprocessing.get_context("spawn")
        entered, release = context.Event(), context.Event()
        calls, results = context.Value("i", 0), context.Queue()
        second_ready = context.Event()
        arguments = (str(self.storage.database_path), self.raw_key, entered, release, calls, results)
        first = context.Process(target=authenticate_in_process, args=arguments)
        second = context.Process(target=authenticate_in_process, args=(*arguments, second_ready))
        first.start()
        try:
            self.assertTrue(entered.wait(3))
            second.start()
            self.assertTrue(second_ready.wait(3))
            release.set()
            self.assertEqual(results.get(timeout=5), ("ok", "user-subject"))
            self.assertEqual(results.get(timeout=5), ("ok", "user-subject"))
        finally:
            release.set()
            for process in (first, second):
                if process.pid is not None:
                    process.join(5)
                    if process.is_alive():
                        process.terminate()
                        process.join(2)
            results.close()
            results.join_thread()
        self.assertEqual([first.exitcode, second.exitcode], [0, 0])
        self.assertEqual(calls.value, 1)

    def test_process_exit_releases_key_lock_and_next_process_recovers(self):
        context = multiprocessing.get_context("spawn")
        entered, release = context.Event(), context.Event()
        path = self.storage.database_path.resolve()
        lock_path = path.parent / (path.name + ".key-locks") / (self.service._hash(self.raw_key) + ".lock")
        owner = context.Process(target=hold_key_lock_in_process, args=(str(lock_path), entered, release))
        owner.start()
        try:
            self.assertTrue(entered.wait(3))
            self.service.timeout_seconds = 0.05
            with patch("api.offline_api_keys.httpx.post") as post:
                with self.assertRaisesRegex(OfflineApiKeyUnavailableError, "waiting"):
                    self.service.authenticate(self.raw_key)
                post.assert_not_called()
        finally:
            owner.terminate()
            owner.join(3)
        self.service.timeout_seconds = 2
        with patch("api.offline_api_keys.httpx.post", return_value=FakeResponse({"access_token": "recovered"})):
            self.assertEqual(self.service.authenticate(self.raw_key)[0]["key_id"], "key-a")


if __name__ == "__main__":
    unittest.main()
