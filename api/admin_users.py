from typing import Any

from api.config import settings
from api.keycloak_admin import KeycloakAdminClient
from api.permissions import VALID_PERMISSIONS
from api.schemas import ManagedUserUpdate, UserProfile
from api.storage import JobStorage
from api.time_utils import utc_now_iso


USER_PERMISSIONS = {
    "firewall.ip.allow",
    "firewall.ip.deny",
    "firewall.ports.allow",
    "firewall.ports.deny",
    "firewall.snapshot.read",
    "firewall.job.read",
}
ADMIN_PERMISSIONS = set(VALID_PERMISSIONS)


class ManagedUserValidationError(ValueError):
    pass


class AdminUserService:
    def __init__(
        self,
        storage: JobStorage,
        keycloak_admin: KeycloakAdminClient,
    ) -> None:
        self.storage = storage
        self.keycloak_admin = keycloak_admin

    def search(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        return self.keycloak_admin.search_users(query, limit)

    def list_users(self) -> list[dict[str, Any]]:
        return self.storage.list_managed_users()

    def update(self, subject_id: str, request: ManagedUserUpdate) -> dict[str, Any]:
        keycloak_user = self.keycloak_admin.get_user(subject_id)
        username = str(keycloak_user.get("username") or "").strip()
        if not username:
            raise ManagedUserValidationError(
                "Keycloak user does not have a valid username."
            )
        if username != request.username:
            raise ManagedUserValidationError(
                "The submitted username does not match the Keycloak user."
            )

        profile = request.profile.value
        permissions = self._permissions_for(profile, request.permissions)
        current = self.storage.get_managed_user(subject_id)

        try:
            # 先改 Keycloak 角色，再写本地业务授权；失败时尽量回滚 Keycloak 角色。
            self.keycloak_admin.set_user_profile(subject_id, profile)
            self.storage.save_managed_user_access(
                subject_id=subject_id,
                username=username,
                display_name=request.display_name,
                profile=profile,
                enabled=request.enabled,
                permissions=permissions,
                allowed_ips=[],
                updated_at=utc_now_iso(),
            )
        except Exception:
            try:
                self.keycloak_admin.set_user_profile(
                    subject_id,
                    current["profile"] if current is not None else None,
                )
            except Exception:
                pass
            raise

        result = self.storage.get_managed_user(subject_id)
        if result is None:
            raise RuntimeError("Managed user was not saved.")
        return result

    @staticmethod
    def _permissions_for(
        profile: str,
        requested: list[str] | None,
    ) -> list[str]:
        allowed = (
            ADMIN_PERMISSIONS
            if profile == UserProfile.admin.value
            else USER_PERMISSIONS
        )
        # 未指定权限时给该 profile 的默认权限，指定后必须落在 profile 允许范围内。
        permissions = (
            allowed
            if requested is None
            else AdminUserService._normalize_requested_permissions(requested)
        )
        unknown = permissions - VALID_PERMISSIONS
        if unknown:
            raise ManagedUserValidationError(
                "Unknown permissions: {0}".format(", ".join(sorted(unknown)))
            )
        forbidden = permissions - allowed
        if forbidden:
            raise ManagedUserValidationError(
                "Profile {0} cannot receive permissions: {1}".format(
                    profile,
                    ", ".join(sorted(forbidden)),
                )
            )
        if not permissions:
            raise ManagedUserValidationError(
                "At least one API permission is required."
            )
        return sorted(permissions)

    @staticmethod
    def _normalize_requested_permissions(requested: list[str]) -> set[str]:
        permissions: set[str] = set()
        for permission in requested:
            normalized = permission.strip().lower()
            # 兼容旧的总权限名，内部仍展开成拆分后的精细权限。
            if normalized == "firewall.allow":
                permissions.update({"firewall.ip.allow", "firewall.ports.allow"})
            elif normalized == "firewall.deny":
                permissions.update({"firewall.ports.deny", "firewall.ip.deny"})
            else:
                permissions.add(normalized)
        return permissions

keycloak_admin_client = KeycloakAdminClient(
    token_url=settings.keycloak_token_url,
    admin_api_url=settings.keycloak_admin_api_url,
    admin_client_id=settings.keycloak_admin_client_id,
    admin_client_secret=settings.keycloak_admin_client_secret,
    resource_client_id=settings.keycloak_client_id,
    user_role=settings.keycloak_user_role,
    admin_role=settings.keycloak_admin_role,
    timeout_seconds=settings.keycloak_http_timeout_seconds,
    ca_cert=settings.keycloak_ca_cert,
)
admin_user_service = AdminUserService(
    JobStorage(settings.database_path),
    keycloak_admin_client,
)
