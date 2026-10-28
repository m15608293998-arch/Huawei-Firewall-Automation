import base64
import hashlib
import secrets
import threading
import time
import uuid
from concurrent.futures import Future, TimeoutError as FutureTimeoutError
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

import httpx
from cryptography.fernet import Fernet, InvalidToken

from api.execution import ExecutionTimeout, exclusive_file_lock
from api.keycloak import (
    InvalidAccessTokenError,
    KeycloakTokenVerifier,
    KeycloakUnavailableError,
)
from api.storage import JobStorage


API_KEY_PREFIX = "sk-"


class OfflineApiKeyError(ValueError):
    pass


class OfflineApiKeyConfigurationError(OfflineApiKeyError):
    pass


class OfflineApiKeyNotFoundError(LookupError):
    pass


class OfflineApiKeyUnavailableError(RuntimeError):
    pass


class OfflineTokenCipher:
    PREFIX = "fernet-v1:"

    def __init__(self, key_material: str) -> None:
        key = base64.urlsafe_b64encode(
            hashlib.sha256(key_material.encode("utf-8")).digest()
        )
        self._fernet = Fernet(key)

    def encrypt(self, token: str) -> str:
        encrypted = self._fernet.encrypt(token.encode("utf-8")).decode("ascii")
        return "{0}{1}".format(self.PREFIX, encrypted)

    def decrypt(self, value: str) -> str:
        if not value.startswith(self.PREFIX):
            raise OfflineApiKeyError("Stored offline token format is invalid.")
        encrypted = value[len(self.PREFIX) :].encode("ascii")
        try:
            return self._fernet.decrypt(encrypted).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError) as exc:
            raise OfflineApiKeyError("Stored offline token could not be decrypted.") from exc


class OfflineApiKeyService:
    LAST_USED_WRITE_INTERVAL = timedelta(minutes=5)

    def __init__(
        self,
        storage: JobStorage,
        token_verifier: KeycloakTokenVerifier,
        authorization_url: str,
        token_url: str,
        client_id: str,
        client_secret: str | None,
        scope: str,
        timeout_seconds: float,
        ca_cert: str | None,
        token_encryption_key: str | None = None,
        authorization_ttl_seconds: int = 300,
        max_keys_per_user: int = 5,
    ) -> None:
        self.storage = storage
        self.token_verifier = token_verifier
        self.authorization_url = authorization_url
        self.token_url = token_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.timeout_seconds = timeout_seconds
        self.ca_cert = ca_cert
        self.authorization_ttl_seconds = authorization_ttl_seconds
        self.max_keys_per_user = max_keys_per_user
        self._token_cipher = (
            OfflineTokenCipher(token_encryption_key.strip())
            if token_encryption_key and token_encryption_key.strip()
            else None
        )
        self._claims_cache: dict[str, tuple[float, dict[str, Any]]] = {}
        self._refreshes: dict[str, Future] = {}
        self._lock = threading.Lock()

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret and self._token_cipher)

    def begin_authorization(
        self,
        subject_id: str,
        label: str,
        redirect_uri: str,
    ) -> dict[str, str]:
        self._require_configured()
        user = self._require_eligible_user(subject_id)
        del user
        if self.storage.count_active_offline_api_keys(subject_id) >= self.max_keys_per_user:
            raise OfflineApiKeyError(
                "The maximum number of active API keys has been reached."
            )

        state = secrets.token_urlsafe(32)
        code_verifier = secrets.token_urlsafe(64)
        # 生成 PKCE challenge，回调时不需要在浏览器保存 client secret。
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        created_at = datetime.now(timezone.utc)
        expires_at = created_at + timedelta(seconds=self.authorization_ttl_seconds)
        self.storage.save_offline_api_key_authorization(
            {
                # state 只存 hash，数据库泄露时也不能直接复用 OAuth 回调。
                "state_hash": self._hash(state),
                "subject_id": subject_id,
                "label": label,
                "code_verifier": code_verifier,
                "redirect_uri": redirect_uri,
                "created_at": created_at.isoformat(),
                "expires_at": expires_at.isoformat(),
            }
        )
        query = urlencode(
            {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": redirect_uri,
                "scope": self.scope,
                "state": state,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        return {
            "authorization_url": "{0}?{1}".format(self.authorization_url, query),
            "expires_at": expires_at.isoformat(),
        }

    def complete_authorization(self, state: str, code: str) -> dict[str, Any]:
        self._require_configured()
        # consume 保证授权码流程只能完成一次，防止回调被重复提交。
        transaction = self.storage.consume_offline_api_key_authorization(
            self._hash(state)
        )
        if transaction is None:
            raise OfflineApiKeyError("API key authorization is invalid or already used.")
        if self._parse_datetime(str(transaction["expires_at"])) <= datetime.now(
            timezone.utc
        ):
            raise OfflineApiKeyError("API key authorization has expired.")

        payload = self._token_request(
            {
                "grant_type": "authorization_code",
                "client_id": self.client_id,
                "client_secret": str(self.client_secret),
                "code": code,
                "redirect_uri": str(transaction["redirect_uri"]),
                "code_verifier": str(transaction["code_verifier"]),
            }
        )
        access_token = payload.get("access_token")
        offline_token = payload.get("refresh_token")
        granted_scope = str(payload.get("scope") or "")
        if not isinstance(access_token, str) or not access_token:
            raise OfflineApiKeyError("Keycloak did not return an access token.")
        if not isinstance(offline_token, str) or not offline_token:
            raise OfflineApiKeyError("Keycloak did not return an offline token.")
        if "offline_access" not in granted_scope.split():
            raise OfflineApiKeyError("Keycloak did not grant offline_access.")

        # 用短 access token 校验登录人，真正发给调用方的是 sk-<offline_token>。
        claims = self._verify_access_token(access_token)
        subject_id = str(transaction["subject_id"])
        if claims.get("sub") != subject_id:
            raise OfflineApiKeyError("The Keycloak user changed during API key creation.")
        self._require_eligible_user(subject_id)
        if self.storage.count_active_offline_api_keys(subject_id) >= self.max_keys_per_user:
            raise OfflineApiKeyError(
                "The maximum number of active API keys has been reached."
            )

        raw_key = API_KEY_PREFIX + offline_token
        token_hash = self._hash(raw_key)
        encrypted_offline_token = self._encrypt_offline_token(offline_token)
        created_at = datetime.now(timezone.utc).isoformat()
        record = {
            "key_id": uuid.uuid4().hex,
            "subject_id": subject_id,
            "label": str(transaction["label"]),
            "token_hash": token_hash,
            "key_hint": "sk-...{0}".format(token_hash[:8]),
            "encrypted_offline_token": encrypted_offline_token,
            "offline_token_updated_at": created_at,
            "created_at": created_at,
            "last_used_at": None,
            "revoked_at": None,
        }
        self.storage.create_offline_api_key(record)
        return {
            **self._public_record(record),
            "api_key": raw_key,
        }

    def authenticate(self, raw_key: str) -> tuple[dict[str, Any], dict[str, Any]]:
        self._require_configured()
        fallback_offline_token = self._parse_offline_token(raw_key)
        token_hash = self._hash(raw_key)
        record = self._active_record(token_hash)
        key_id = str(record["key_id"])
        with self._lock:
            cached = self._claims_cache.get(key_id)
            refresh = self._refreshes.get(key_id)
            cache_valid = cached is not None and time.time() < cached[0]
            leader = False
            if not cache_valid:
                leader = refresh is None
                if leader:
                    refresh = Future()
                    self._refreshes[key_id] = refresh

        if cache_valid:
            claims = cached[1]
        else:
            if leader:
                try:
                    cached = self._refresh_claims(token_hash, fallback_offline_token)
                except BaseException as exc:
                    if isinstance(exc, Exception) and not isinstance(exc, (OfflineApiKeyError, OfflineApiKeyUnavailableError)):
                        exc = OfflineApiKeyUnavailableError("Unable to refresh API key authorization.")
                    refresh.set_exception(exc)
                else:
                    with self._lock:
                        self._claims_cache[key_id] = cached
                    refresh.set_result(cached)
                finally:
                    with self._lock:
                        self._refreshes.pop(key_id, None)
            try:
                _, claims = refresh.result(timeout=self.timeout_seconds)
            except FutureTimeoutError as exc:
                raise OfflineApiKeyUnavailableError("Timed out waiting for API key refresh.") from exc

        # Revocation and disabling remain effective even if they race a slow
        # refresh. Never hold the cache lock while reading storage or the network.
        record = self._active_record(token_hash)
        if float(claims.get("exp") or 0) <= time.time():
            raise OfflineApiKeyUnavailableError("Refreshed API key authorization has expired; retry.")
        self._touch_if_needed(record)
        return self._public_record(record), claims

    def _active_record(self, token_hash: str) -> dict[str, Any]:
        record = self.storage.get_offline_api_key_by_hash(token_hash)
        if record is None:
            raise OfflineApiKeyError("Invalid API key.")
        if record.get("revoked_at"):
            raise OfflineApiKeyError("API key has been revoked.")
        self._require_eligible_user(str(record["subject_id"]))
        return record

    def _refresh_claims(self, token_hash: str, fallback_offline_token: str) -> tuple[float, dict[str, Any]]:
        # Kernel locks coordinate API processes and are released on process exit.
        # A different key never waits for this key's network request.
        database_path = self.storage.database_path.resolve()
        lock_path = database_path.parent / (database_path.name + ".key-locks") / (token_hash + ".lock")
        try:
            with exclusive_file_lock(lock_path, self.timeout_seconds):
                record = self._active_record(token_hash)
                access_token = record.get("encrypted_access_token")
                usable_until = float(record.get("access_token_usable_until") or 0)
                if access_token and time.time() < usable_until:
                    try:
                        claims = self._verify_access_token(self._token_cipher.decrypt(access_token))
                        if claims.get("sub") != record["subject_id"]:
                            raise OfflineApiKeyError("API key subject does not match Keycloak.")
                    except OfflineApiKeyError:
                        # An expired/retired signing key must not pin a new API
                        # process to unusable cached authorization.
                        pass
                    else:
                        return min(usable_until, float(claims.get("exp") or 0) - 30.0), claims

                payload, record = self._refresh_offline_token(
                    record, self._offline_token_for_record(record, fallback_offline_token),
                )
                rotated_token = payload.get("refresh_token")
                if isinstance(rotated_token, str) and rotated_token:
                    encrypted = self._encrypt_offline_token(rotated_token)
                    updated_at = datetime.now(timezone.utc).isoformat()
                    if not self.storage.update_offline_api_key_token(
                        str(record["key_id"]), encrypted, updated_at, expected_record=record,
                    ):
                        self._active_record(token_hash)
                        raise OfflineApiKeyUnavailableError("API key token changed during refresh; retry.")
                    record = {**record, "encrypted_offline_token": encrypted, "offline_token_updated_at": updated_at}
                # Persist rotation before JWT verification: a temporary JWKS
                # outage must not lose the newly issued refresh token.
                access_token = payload.get("access_token")
                if not isinstance(access_token, str) or not access_token:
                    raise OfflineApiKeyError("Keycloak did not return an access token.")
                claims = self._verify_access_token(access_token)
                if claims.get("sub") != record["subject_id"]:
                    raise OfflineApiKeyError("API key subject does not match Keycloak.")
                usable_until = float(claims.get("exp") or 0) - 30.0
                if not self.storage.cache_offline_api_key_access_token(
                    record, self._encrypt_offline_token(access_token), usable_until,
                ):
                    self._active_record(token_hash)
                    raise OfflineApiKeyUnavailableError("API key token changed during refresh; retry.")
                return usable_until, claims
        except ExecutionTimeout as exc:
            raise OfflineApiKeyUnavailableError("Timed out waiting for API key refresh.") from exc

    def list(self, subject_id: str) -> list[dict[str, Any]]:
        return self.storage.list_offline_api_keys(subject_id)

    def update_label(
        self,
        subject_id: str,
        key_id: str,
        label: str,
    ) -> dict[str, Any]:
        record = self.storage.update_offline_api_key_label(
            subject_id,
            key_id,
            label,
        )
        if record is None:
            raise OfflineApiKeyNotFoundError("Active API key was not found.")
        return record

    def revoke(self, subject_id: str, key_id: str) -> None:
        if not self.storage.revoke_offline_api_key(
            subject_id,
            key_id,
            datetime.now(timezone.utc).isoformat(),
        ):
            raise OfflineApiKeyNotFoundError("Active API key was not found.")
        with self._lock:
            self._claims_cache.pop(key_id, None)

    @staticmethod
    def is_api_key(value: str) -> bool:
        return value.startswith(API_KEY_PREFIX)

    def _require_configured(self) -> None:
        if not self.configured:
            raise OfflineApiKeyConfigurationError(
                "Keycloak offline API key client and token encryption key are not configured."
            )

    def _require_eligible_user(self, subject_id: str) -> dict[str, Any]:
        # 离线 Key 只给已纳管的普通用户，管理员仍走管理端登录。
        user = self.storage.get_managed_user(subject_id)
        if user is None:
            raise OfflineApiKeyError("The Keycloak user has no saved business access.")
        if not user["enabled"]:
            raise OfflineApiKeyError("The user bound to this API key is disabled.")
        if user["profile"] != "user":
            raise OfflineApiKeyError("Administrator accounts cannot use personal API keys.")
        return user

    def _token_request(self, data: dict[str, str]) -> dict[str, Any]:
        verify: bool | str = self.ca_cert or True
        try:
            response = httpx.post(
                self.token_url,
                data=data,
                timeout=self.timeout_seconds,
                verify=verify,
            )
        except httpx.HTTPError as exc:
            raise OfflineApiKeyUnavailableError(
                "Unable to reach the Keycloak token endpoint."
            ) from exc
        try:
            payload = response.json() if response.content else {}
        except ValueError:
            payload = {}
        if response.is_success and isinstance(payload, dict):
            return payload
        detail = (
            payload.get("error_description") or payload.get("error")
            if isinstance(payload, dict)
            else None
        )
        if response.status_code in {400, 401}:
            raise OfflineApiKeyError(str(detail or "Keycloak rejected the API key."))
        raise OfflineApiKeyUnavailableError(
            str(detail or "Keycloak token exchange failed.")
        )

    def _refresh_offline_token(
        self,
        record: dict[str, Any],
        offline_token: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        try:
            return self._refresh_once(offline_token), record
        except OfflineApiKeyError:
            latest = self.storage.get_offline_api_key_by_hash(str(record["token_hash"]))
            if latest is None or latest.get("revoked_at"):
                raise
            if not self._stored_token_changed(record, latest):
                raise
            latest_token = self._offline_token_for_record(latest, offline_token)
            return self._refresh_once(latest_token), latest

    def _refresh_once(self, offline_token: str) -> dict[str, Any]:
        return self._token_request(
            {
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "client_secret": str(self.client_secret),
                "refresh_token": offline_token,
            }
        )

    def _verify_access_token(self, token: str) -> dict[str, Any]:
        try:
            claims = self.token_verifier.verify(token)
        except InvalidAccessTokenError as exc:
            raise OfflineApiKeyError(str(exc)) from exc
        except KeycloakUnavailableError as exc:
            raise OfflineApiKeyUnavailableError(str(exc)) from exc
        client_id = claims.get("azp") or claims.get("clientId")
        if client_id != self.client_id:
            raise OfflineApiKeyError("Access token was issued to an unexpected client.")
        return claims

    def _touch_if_needed(self, record: dict[str, Any]) -> None:
        # last_used_at 不必每次请求都写库，降低高频调用时的 SQLite 写压力。
        now = datetime.now(timezone.utc)
        last_used_at = record.get("last_used_at")
        if last_used_at is None or now - self._parse_datetime(
            str(last_used_at)
        ) >= self.LAST_USED_WRITE_INTERVAL:
            self.storage.touch_offline_api_key(str(record["key_id"]), now.isoformat())

    @staticmethod
    def _parse_offline_token(raw_key: str) -> str:
        if not raw_key.startswith(API_KEY_PREFIX):
            raise OfflineApiKeyError("Invalid API key format.")
        offline_token = raw_key[len(API_KEY_PREFIX) :].strip()
        if len(offline_token) < 32 or any(character.isspace() for character in offline_token):
            raise OfflineApiKeyError("Invalid API key format.")
        return offline_token

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _encrypt_offline_token(self, token: str) -> str:
        if self._token_cipher is None:
            raise OfflineApiKeyConfigurationError(
                "Offline API key token encryption key is not configured."
            )
        return self._token_cipher.encrypt(token)

    def _offline_token_for_record(
        self,
        record: dict[str, Any],
        fallback_offline_token: str,
    ) -> str:
        encrypted_offline_token = record.get("encrypted_offline_token")
        if isinstance(encrypted_offline_token, str) and encrypted_offline_token:
            if self._token_cipher is None:
                raise OfflineApiKeyConfigurationError(
                    "Offline API key token encryption key is not configured."
                )
            return self._token_cipher.decrypt(encrypted_offline_token)
        return fallback_offline_token

    @staticmethod
    def _stored_token_changed(
        old_record: dict[str, Any],
        new_record: dict[str, Any],
    ) -> bool:
        return (
            new_record.get("offline_token_updated_at")
            != old_record.get("offline_token_updated_at")
            or new_record.get("encrypted_offline_token")
            != old_record.get("encrypted_offline_token")
        )

    @staticmethod
    def _public_record(record: dict[str, Any]) -> dict[str, Any]:
        hidden_fields = {
            "token_hash",
            "encrypted_offline_token",
            "offline_token_updated_at",
            "encrypted_access_token",
            "access_token_usable_until",
        }
        return {key: value for key, value in record.items() if key not in hidden_fields}
