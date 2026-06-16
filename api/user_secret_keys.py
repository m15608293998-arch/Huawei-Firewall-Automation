import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from api.storage import JobStorage
from api.time_utils import utc_now_iso


SECRET_KEY_PREFIX = "sk1"


class UserSecretKeyError(ValueError):
    pass


class UserSecretKeyNotFoundError(LookupError):
    pass


class UserSecretKeyService:
    LAST_USED_WRITE_INTERVAL = timedelta(minutes=5)

    def __init__(self, storage: JobStorage) -> None:
        self.storage = storage

    def create(
        self,
        subject_id: str,
        created_by: str,
        label: str | None,
        expires_in_days: int,
    ) -> dict[str, Any]:
        user = self.storage.get_managed_user(subject_id)
        if user is None:
            raise UserSecretKeyNotFoundError(
                "Save this Keycloak user authorization before issuing an SK."
            )
        if not user["enabled"]:
            raise UserSecretKeyError("Cannot issue an SK for a disabled user.")
        if user["profile"] != "user":
            raise UserSecretKeyError("Administrator accounts cannot receive a user SK.")

        key_id = uuid.uuid4().hex
        raw_key = "{0}.{1}.{2}".format(
            SECRET_KEY_PREFIX,
            key_id,
            secrets.token_urlsafe(32),
        )
        created_at = datetime.now(timezone.utc)
        expires_at = created_at + timedelta(days=expires_in_days)
        created = self.storage.create_user_secret_key(
            {
                "key_id": key_id,
                "subject_id": subject_id,
                "label": label,
                "key_hash": self._hash(raw_key),
                "key_prefix": raw_key[:18],
                "created_by": created_by,
                "created_at": created_at.isoformat(),
                "expires_at": expires_at.isoformat(),
                "last_used_at": None,
                "revoked_at": None,
            }
        )
        if not created:
            raise UserSecretKeyError(
                "This user already has an active SK. Revoke it before issuing a new one."
            )
        result = self._public_record(self.storage.get_user_secret_key(key_id))
        result["secret_key"] = raw_key
        return result

    def list(self, subject_id: str) -> list[dict[str, Any]]:
        if self.storage.get_managed_user(subject_id) is None:
            raise UserSecretKeyNotFoundError("Managed Keycloak user was not found.")
        return self.storage.list_user_secret_keys(subject_id)

    def revoke(self, subject_id: str, key_id: str) -> None:
        if not self.storage.revoke_user_secret_key(
            subject_id,
            key_id,
            utc_now_iso(),
        ):
            raise UserSecretKeyNotFoundError("Active user SK was not found.")

    def verify(self, raw_key: str) -> tuple[dict[str, Any], dict[str, Any]]:
        key_id = self._parse_key_id(raw_key)
        record = self.storage.get_user_secret_key(key_id)
        if record is None or not hmac.compare_digest(
            str(record["key_hash"]),
            self._hash(raw_key),
        ):
            raise UserSecretKeyError("Invalid user SK.")
        if record.get("revoked_at"):
            raise UserSecretKeyError("User SK has been revoked.")
        if self._parse_datetime(str(record["expires_at"])) <= datetime.now(
            timezone.utc
        ):
            raise UserSecretKeyError("User SK has expired.")

        user = self.storage.get_managed_user(str(record["subject_id"]))
        if user is None or not user["enabled"]:
            raise UserSecretKeyError("The user bound to this SK is disabled.")
        if user["profile"] != "user":
            raise UserSecretKeyError("This SK is no longer valid for the user profile.")

        now = datetime.now(timezone.utc)
        last_used_at = record.get("last_used_at")
        if last_used_at is None or now - self._parse_datetime(
            str(last_used_at)
        ) >= self.LAST_USED_WRITE_INTERVAL:
            self.storage.touch_user_secret_key(key_id, now.isoformat())
        return self._public_record(record), user

    @staticmethod
    def is_secret_key(value: str) -> bool:
        return value.startswith(SECRET_KEY_PREFIX + ".")

    @staticmethod
    def _parse_key_id(raw_key: str) -> str:
        parts = raw_key.strip().split(".")
        if len(parts) != 3 or parts[0] != SECRET_KEY_PREFIX:
            raise UserSecretKeyError("Invalid user SK format.")
        key_id = parts[1]
        if len(key_id) != 32 or any(
            character not in "0123456789abcdef" for character in key_id
        ):
            raise UserSecretKeyError("Invalid user SK format.")
        return key_id

    @staticmethod
    def _hash(raw_key: str) -> str:
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _public_record(record: dict[str, Any] | None) -> dict[str, Any]:
        if record is None:
            raise UserSecretKeyNotFoundError("User SK was not found.")
        return {key: value for key, value in record.items() if key != "key_hash"}
