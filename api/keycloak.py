import threading
import time
from typing import Any, Callable

import httpx
import jwt


class InvalidAccessTokenError(Exception):
    pass


class KeycloakUnavailableError(Exception):
    pass


class KeycloakTokenVerifier:
    def __init__(
        self,
        issuer: str,
        audience: str,
        jwks_url: str,
        timeout_seconds: float = 5.0,
        cache_seconds: float = 300.0,
        ca_cert: str | None = None,
        jwks_fetcher: Callable[[], dict[str, Any]] | None = None,
        refresh_min_interval_seconds: float = 10.0,
    ) -> None:
        if cache_seconds <= 0 or refresh_min_interval_seconds <= 0:
            raise ValueError("JWKS cache and refresh intervals must be positive.")
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.jwks_url = jwks_url
        self.timeout_seconds = timeout_seconds
        self.cache_seconds = cache_seconds
        self.ca_cert = ca_cert
        self.jwks_fetcher = jwks_fetcher
        self.refresh_min_interval_seconds = min(refresh_min_interval_seconds, cache_seconds)
        self._keys: dict[str, dict[str, Any]] = {}
        self._cache_expires_at = 0.0
        self._refresh_after = 0.0
        self._refreshing = False
        self._condition = threading.Condition()

    def verify(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise InvalidAccessTokenError("Malformed access token.") from exc

        # 只接受 Keycloak 当前配置使用的 RS256，避免降级到非预期算法。
        if header.get("alg") != "RS256":
            raise InvalidAccessTokenError("Access token must use RS256.")

        key_id = header.get("kid")
        if not isinstance(key_id, str) or not key_id:
            raise InvalidAccessTokenError("Access token is missing kid.")

        jwk = self._get_jwk(key_id)
        try:
            public_key = jwt.PyJWK.from_dict(jwk, algorithm="RS256").key
            claims = jwt.decode(
                token,
                key=public_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iat", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidAccessTokenError("Access token validation failed.") from exc

        if not isinstance(claims, dict):
            raise InvalidAccessTokenError("Access token claims are invalid.")
        return claims

    def _get_jwk(self, key_id: str) -> dict[str, Any]:
        with self._condition:
            while True:
                now = time.monotonic()
                jwk = self._keys.get(key_id)
                if now < self._cache_expires_at and jwk is not None:
                    return jwk
                if self._refreshing:
                    if not self._condition.wait_for(lambda: not self._refreshing, self.timeout_seconds):
                        raise KeycloakUnavailableError("Timed out waiting for Keycloak signing keys.")
                    continue
                if now < self._refresh_after:
                    if now >= self._cache_expires_at:
                        raise KeycloakUnavailableError("Keycloak signing keys are temporarily unavailable.")
                    raise InvalidAccessTokenError("Access token signing key is unknown.")
                self._refreshing = True
                break

        # Network I/O must not hold the cache lock: known, unexpired keys remain
        # usable while an unrelated kid triggers a refresh.
        try:
            keys = self._refresh_jwks()
        except Exception:
            with self._condition:
                self._refresh_after = time.monotonic() + self.refresh_min_interval_seconds
                self._refreshing = False
                self._condition.notify_all()
            raise
        with self._condition:
            self._keys = keys
            self._cache_expires_at = time.monotonic() + self.cache_seconds
            # One complete JWKS also negatively caches every unknown kid for
            # this interval, without retaining attacker-controlled identifiers.
            self._refresh_after = time.monotonic() + self.refresh_min_interval_seconds
            self._refreshing = False
            self._condition.notify_all()
            jwk = self._keys.get(key_id)
        if jwk is None:
            raise InvalidAccessTokenError("Access token signing key is unknown.")
        return jwk

    def _refresh_jwks(self) -> dict[str, dict[str, Any]]:
        try:
            if self.jwks_fetcher is not None:
                payload = self.jwks_fetcher()
            else:
                verify: bool | str = self.ca_cert or True
                response = httpx.get(
                    self.jwks_url,
                    timeout=self.timeout_seconds,
                    verify=verify,
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise KeycloakUnavailableError(
                "Unable to load Keycloak signing keys."
            ) from exc

        keys = payload.get("keys") if isinstance(payload, dict) else None
        if not isinstance(keys, list):
            raise KeycloakUnavailableError("Keycloak JWKS response is invalid.")

        return {
            str(key["kid"]): key
            for key in keys
            if isinstance(key, dict) and key.get("kid")
        }
