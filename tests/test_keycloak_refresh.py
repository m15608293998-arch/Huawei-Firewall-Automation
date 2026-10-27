import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from api.keycloak import InvalidAccessTokenError, KeycloakTokenVerifier, KeycloakUnavailableError


class KeycloakRefreshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.rotated_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.old_jwk = {**jwt.algorithms.RSAAlgorithm.to_jwk(cls.signing_key.public_key(), as_dict=True), "kid": "old"}
        cls.new_jwk = {**jwt.algorithms.RSAAlgorithm.to_jwk(cls.rotated_key.public_key(), as_dict=True), "kid": "new"}

    def setUp(self):
        self.clock = 100.0
        self.fetch = Mock(return_value={"keys": [self.old_jwk]})
        self.verifier = KeycloakTokenVerifier(
            issuer="https://keycloak.example/realms/test", audience="firewall",
            jwks_url="https://keycloak.example/certs", jwks_fetcher=self.fetch,
        )
        self.monotonic = patch("api.keycloak.time.monotonic", side_effect=lambda: self.clock)
        self.monotonic.start()
        self.addCleanup(self.monotonic.stop)

    def token(self, kid="old", key=None):
        now = int(time.time())
        return jwt.encode({
            "sub": "user", "iss": self.verifier.issuer, "aud": "firewall",
            "iat": now, "exp": now + 300,
        }, key or self.signing_key, algorithm="RS256", headers={"kid": kid})

    def reject_unknown(self, kid):
        with self.assertRaises(InvalidAccessTokenError):
            self.verifier.verify(self.token(kid))

    def test_repeated_and_random_unknown_kids_share_refresh_cooldown(self):
        for kid in ["missing"] * 5 + ["random-" + str(index) for index in range(8)]:
            self.reject_unknown(kid)
        self.assertEqual(self.fetch.call_count, 1)

    def test_concurrent_unknown_kids_share_one_refresh(self):
        entered, release = threading.Event(), threading.Event()

        def fetch():
            entered.set()
            if not release.wait(2):
                raise AssertionError("JWKS fixture was not released")
            return {"keys": [self.old_jwk]}

        self.fetch.side_effect = fetch
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(self.reject_unknown, "random-" + str(index)) for index in range(8)]
            try:
                self.assertTrue(entered.wait(1))
            finally:
                release.set()
            for future in futures:
                future.result(timeout=2)
        self.assertEqual(self.fetch.call_count, 1)

    def test_valid_cached_key_does_not_wait_for_unknown_key_network_refresh(self):
        self.verifier.verify(self.token())
        self.clock += 11
        entered, release = threading.Event(), threading.Event()

        def fetch():
            entered.set()
            if not release.wait(2):
                raise AssertionError("JWKS fixture was not released")
            return {"keys": [self.old_jwk]}

        self.fetch.side_effect = fetch
        with ThreadPoolExecutor(max_workers=2) as pool:
            unknown = pool.submit(self.reject_unknown, "missing")
            try:
                self.assertTrue(entered.wait(1))
                known = pool.submit(self.verifier.verify, self.token())
                self.assertEqual(known.result(timeout=0.3)["sub"], "user")
            finally:
                release.set()
            unknown.result(timeout=2)

    def test_rotation_is_loaded_after_cooldown_and_removed_key_is_rejected(self):
        self.verifier.verify(self.token())
        self.fetch.return_value = {"keys": [self.new_jwk]}
        self.clock += 1
        with self.assertRaises(InvalidAccessTokenError):
            self.verifier.verify(self.token("new", self.rotated_key))
        self.assertEqual(self.fetch.call_count, 1)
        self.clock += 10
        self.assertEqual(self.verifier.verify(self.token("new", self.rotated_key))["sub"], "user")
        self.reject_unknown("old")
        self.assertEqual(self.fetch.call_count, 2)

    def test_network_failure_is_cooled_down_and_later_recovers(self):
        self.fetch.side_effect = httpx.ConnectError("local test outage")
        for _ in range(5):
            with self.assertRaises(KeycloakUnavailableError):
                self.verifier.verify(self.token())
        self.assertEqual(self.fetch.call_count, 1)
        self.clock += 11
        self.fetch.side_effect = None
        self.assertEqual(self.verifier.verify(self.token())["sub"], "user")
        self.assertEqual(self.fetch.call_count, 2)

    def test_expired_keys_are_not_used_when_refresh_fails(self):
        self.verifier.verify(self.token())
        self.clock += 301
        self.fetch.side_effect = httpx.ConnectError("local test outage")
        for _ in range(2):
            with self.assertRaises(KeycloakUnavailableError):
                self.verifier.verify(self.token())
        self.assertEqual(self.fetch.call_count, 2)

    def test_matching_kid_does_not_bypass_signature_validation(self):
        self.verifier.verify(self.token())
        with self.assertRaises(InvalidAccessTokenError):
            self.verifier.verify(self.token("old", self.rotated_key))
        self.assertEqual(self.fetch.call_count, 1)

    def test_waiter_times_out_without_canceling_the_shared_refresh(self):
        self.verifier.timeout_seconds = 0.05
        entered, release = threading.Event(), threading.Event()

        def fetch():
            entered.set()
            if not release.wait(2):
                raise AssertionError("JWKS fixture was not released")
            return {"keys": [self.old_jwk]}

        self.fetch.side_effect = fetch
        with ThreadPoolExecutor(max_workers=1) as pool:
            unknown = pool.submit(self.reject_unknown, "missing")
            try:
                self.assertTrue(entered.wait(1))
                with self.assertRaisesRegex(KeycloakUnavailableError, "waiting"):
                    self.verifier.verify(self.token())
                self.assertFalse(unknown.done())
            finally:
                release.set()
            unknown.result(timeout=2)
        self.assertEqual(self.verifier.verify(self.token())["sub"], "user")
        self.assertEqual(self.fetch.call_count, 1)

    def test_bad_refresh_does_not_replace_unexpired_cached_keys(self):
        self.verifier.verify(self.token())
        self.clock += 11
        self.fetch.return_value = {"keys": None}
        with self.assertRaises(KeycloakUnavailableError):
            self.verifier.verify(self.token("missing"))
        self.assertEqual(self.verifier.verify(self.token())["sub"], "user")
        self.reject_unknown("another-missing")
        self.assertEqual(self.fetch.call_count, 2)

    def test_shorter_cache_ttl_is_not_blocked_by_successful_refresh_cooldown(self):
        verifier = KeycloakTokenVerifier(
            issuer=self.verifier.issuer, audience="firewall", jwks_url="https://keycloak.example/certs",
            cache_seconds=3, jwks_fetcher=self.fetch,
        )
        verifier.verify(self.token())
        self.clock += 4
        self.assertEqual(verifier.verify(self.token())["sub"], "user")
        self.assertEqual(self.fetch.call_count, 2)


if __name__ == "__main__":
    unittest.main()
