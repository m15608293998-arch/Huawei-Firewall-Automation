from typing import Any

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from api.config import settings
from api.keycloak import (
    InvalidAccessTokenError,
    KeycloakTokenVerifier,
    KeycloakUnavailableError,
)
from api.offline_api_keys import (
    OfflineApiKeyConfigurationError,
    OfflineApiKeyError,
    OfflineApiKeyService,
    OfflineApiKeyUnavailableError,
)
from api.permissions import (
    FIREWALL_ALLOW,
    FIREWALL_DENY,
    FIREWALL_JOB_AUDIT,
    FIREWALL_JOB_READ,
    IDENTITY_USER_MANAGE,
    VALID_PERMISSIONS,
)
from api.schemas import TradeAccessJobCreate
from api.storage import JobStorage
from api.user_secret_keys import UserSecretKeyError, UserSecretKeyService


class Principal(BaseModel):
    subject_id: str
    subject: str
    auth_type: str
    roles: list[str] = Field(default_factory=list)
    client_id: str | None = None
    subject_type: str = "user"
    access_enabled: bool = True
    permissions: list[str] = Field(default_factory=list)
    allowed_ips: list[str] = Field(default_factory=list)
    key_id: str | None = None

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

    @property
    def is_admin(self) -> bool:
        return self.has_role(settings.keycloak_admin_role)


permission_storage = JobStorage(settings.database_path)
user_secret_key_service = UserSecretKeyService(permission_storage)
token_verifier = KeycloakTokenVerifier(
    issuer=settings.keycloak_issuer,
    audience=settings.keycloak_client_id,
    jwks_url=settings.keycloak_jwks_url,
    timeout_seconds=settings.keycloak_http_timeout_seconds,
    cache_seconds=settings.keycloak_jwks_cache_seconds,
    ca_cert=settings.keycloak_ca_cert,
)
offline_api_key_service = OfflineApiKeyService(
    storage=permission_storage,
    token_verifier=token_verifier,
    authorization_url=settings.keycloak_authorization_url,
    token_url=settings.keycloak_token_url,
    client_id=settings.keycloak_offline_client_id,
    client_secret=settings.keycloak_offline_client_secret,
    scope=settings.keycloak_offline_scope,
    timeout_seconds=settings.keycloak_http_timeout_seconds,
    ca_cert=settings.keycloak_ca_cert,
    authorization_ttl_seconds=settings.offline_api_key_authorization_ttl_seconds,
    max_keys_per_user=settings.offline_api_key_max_per_user,
)
bearer_scheme = HTTPBearer(
    auto_error=False,
    bearerFormat="JWT or sk- API key",
    description="Keycloak access token or offline API key",
)


def principal_from_user_secret_key(raw_key: str) -> Principal:
    record, user = user_secret_key_service.verify(raw_key)
    subject_id = str(user["subject_id"])
    return Principal(
        subject_id=subject_id,
        subject=str(user["username"]),
        auth_type="user_secret_key",
        roles=[settings.keycloak_user_role],
        client_id=None,
        subject_type="user",
        access_enabled=bool(user["enabled"]),
        permissions=permission_storage.get_subject_permissions(subject_id),
        allowed_ips=permission_storage.get_subject_allowed_ips(subject_id),
        key_id=str(record["key_id"]),
    )


def principal_from_offline_api_key(raw_key: str) -> Principal:
    record, claims = offline_api_key_service.authenticate(raw_key)
    principal = principal_from_claims(claims, auth_type="offline_api_key")
    return principal.model_copy(update={"key_id": str(record["key_id"])})


def principal_from_claims(
    claims: dict[str, Any],
    auth_type: str = "keycloak_bearer",
) -> Principal:
    subject_id = claims.get("sub")
    if not isinstance(subject_id, str) or not subject_id:
        raise InvalidAccessTokenError("Access token is missing sub.")

    resource_access = claims.get("resource_access") or {}
    client_access = (
        resource_access.get(settings.keycloak_client_id, {})
        if isinstance(resource_access, dict)
        else {}
    )
    raw_roles = client_access.get("roles", []) if isinstance(client_access, dict) else []
    roles = sorted({str(role) for role in raw_roles if isinstance(role, str)})

    raw_client_id = claims.get("azp") or claims.get("clientId")
    client_id = str(raw_client_id) if raw_client_id else None
    managed_user = permission_storage.get_managed_user(subject_id)
    permissions = permission_storage.get_subject_permissions(subject_id)
    allowed_ips = permission_storage.get_subject_allowed_ips(subject_id)
    access_enabled = bool(managed_user.get("enabled", True)) if managed_user else True
    subject = claims.get("preferred_username") or client_id or subject_id
    resolved_auth_type = auth_type
    if client_id == settings.keycloak_admin_browser_client_id:
        resolved_auth_type = "keycloak_admin_bearer"
    return Principal(
        subject_id=subject_id,
        subject=str(subject),
        auth_type=resolved_auth_type,
        roles=roles,
        client_id=client_id,
        subject_type="user",
        access_enabled=access_enabled,
        permissions=permissions,
        allowed_ips=allowed_ips,
    )


def authenticate_request(
    credentials: HTTPAuthorizationCredentials | None,
) -> Principal:
    if not settings.auth_enabled:
        return Principal(
            subject_id=settings.development_subject,
            subject=settings.development_subject,
            auth_type="development",
            roles=[settings.keycloak_user_role, settings.keycloak_admin_role],
            client_id=settings.development_subject,
            subject_type="user",
            permissions=sorted(VALID_PERMISSIONS),
            allowed_ips=[],
        )

    try:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Bearer credential.",
            )
        access_token = credentials.credentials.strip()
        if not access_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing Bearer credential.",
            )
        if offline_api_key_service.is_api_key(access_token):
            try:
                return principal_from_offline_api_key(access_token)
            except OfflineApiKeyConfigurationError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=str(exc),
                ) from exc
            except OfflineApiKeyUnavailableError as exc:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=str(exc),
                ) from exc
            except OfflineApiKeyError as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(exc),
                ) from exc
        if user_secret_key_service.is_secret_key(access_token):
            if not settings.legacy_user_secret_key_auth_enabled:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User SK authentication is disabled; use a Keycloak access token.",
                )
            try:
                return principal_from_user_secret_key(access_token)
            except UserSecretKeyError as exc:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=str(exc),
                ) from exc
        return principal_from_claims(token_verifier.verify(access_token))
    except InvalidAccessTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc
    except KeycloakUnavailableError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc


def get_principal(
    credentials: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> Principal:
    return authenticate_request(credentials)


def require_trade_access_user(
    principal: Principal = Depends(get_principal),
) -> Principal:
    if not principal.access_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This subject is disabled for trade access.",
        )
    allowed_roles = {settings.keycloak_user_role, settings.keycloak_admin_role}
    if not allowed_roles.intersection(principal.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A trade-access user or administrator role is required.",
        )
    return principal


def require_trade_access_admin(
    principal: Principal = Depends(get_principal),
) -> Principal:
    if principal.auth_type != "keycloak_admin_bearer" and settings.auth_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator APIs require the trade-access administrator portal.",
        )
    if not principal.access_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This subject is disabled for trade access.",
        )
    if not principal.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The trade-access administrator role is required.",
        )
    return principal


def require_permission(principal: Principal, permission: str) -> Principal:
    if not principal.has_permission(permission):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This subject is not allowed to access this API operation.",
        )
    return principal


def require_firewall_allow(
    principal: Principal = Depends(require_trade_access_user),
) -> Principal:
    return require_permission(principal, FIREWALL_ALLOW)


def require_firewall_deny(
    principal: Principal = Depends(require_trade_access_user),
) -> Principal:
    return require_permission(principal, FIREWALL_DENY)


def require_firewall_job_read(
    principal: Principal = Depends(require_trade_access_user),
) -> Principal:
    return require_permission(principal, FIREWALL_JOB_READ)


def require_firewall_job_audit(
    principal: Principal = Depends(require_trade_access_admin),
) -> Principal:
    return require_permission(principal, FIREWALL_JOB_AUDIT)


def require_identity_user_manage(
    principal: Principal = Depends(require_trade_access_admin),
) -> Principal:
    require_trade_access_admin(principal)
    return require_permission(principal, IDENTITY_USER_MANAGE)


def authorize_trade_access_request(
    principal: Principal,
    request: TradeAccessJobCreate,
) -> None:
    if not principal.is_admin and request.mask != 32:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Ordinary users may only operate on a single IPv4 address (/32).",
        )
    if not principal.is_admin and request.target_ip not in principal.allowed_ips:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Target IP is not assigned to this user.",
        )


def authorize_job_read(principal: Principal, job: dict[str, Any]) -> None:
    if job.get("principal_id") != principal.subject_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job not found.",
        )
