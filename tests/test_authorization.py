import base64
import time
import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import ValidationError
from unittest.mock import patch

from api.auth import (
    Principal,
    authenticate_request,
    authorize_job_read,
    authorize_trade_access_request,
    principal_from_claims,
    get_principal,
    require_trade_access_admin,
    require_trade_access_user,
    require_firewall_allow,
    require_firewall_deny,
    require_firewall_ip_allow,
    require_firewall_ip_deny,
    require_firewall_ports_allow,
    require_firewall_ports_deny,
    require_identity_user_manage,
)
from api.config import settings
from api.keycloak import (
    InvalidAccessTokenError,
    KeycloakTokenVerifier,
)
from api.permissions import VALID_PERMISSIONS
from api.schemas import (
    TradeAccessAllowRequest,
    TradeAccessDenyRequest,
    TradeAccessJobCreate,
    TradeAccessPortDenyRequest,
)


def base64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).rstrip(b"=").decode()


def create_signing_key() -> tuple[object, dict[str, str]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()
    return private_key, {
        "kty": "RSA",
        "kid": "test-key",
        "use": "sig",
        "alg": "RS256",
        "n": base64url_uint(numbers.n),
        "e": base64url_uint(numbers.e),
    }


def user_principal(subject_id: str = "user-subject") -> Principal:
    return Principal(
        subject_id=subject_id,
        subject="employee-a",
        auth_type="keycloak",
        roles=[settings.keycloak_user_role],
        client_id="trade-access-user-client",
        permissions=sorted(VALID_PERMISSIONS - {"firewall.job.audit"}),
        allowed_ips=["192.168.5.224", "192.168.66.22"],
    )


def admin_principal(subject_id: str = "admin-subject") -> Principal:
    return Principal(
        subject_id=subject_id,
        subject="network-admin-a",
        auth_type="keycloak_admin_bearer",
        roles=[settings.keycloak_admin_role],
        client_id="trade-access-admin-client",
        permissions=sorted(VALID_PERMISSIONS),
        allowed_ips=[],
    )


class KeycloakTokenVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key, self.jwk = create_signing_key()
        self.issuer = "https://keycloak.example/realms/trade-access"
        self.audience = "trade-access-api"
        self.verifier = KeycloakTokenVerifier(
            issuer=self.issuer,
            audience=self.audience,
            jwks_url="https://keycloak.example/certs",
            jwks_fetcher=lambda: {"keys": [self.jwk]},
        )

    def create_token(self, **overrides) -> str:
        now = int(time.time())
        claims = {
            "sub": "subject-1",
            "iss": self.issuer,
            "aud": self.audience,
            "iat": now,
            "exp": now + 300,
        }
        claims.update(overrides)
        return jwt.encode(
            claims,
            self.private_key,
            algorithm="RS256",
            headers={"kid": "test-key"},
        )

    def test_valid_keycloak_access_token_is_verified(self) -> None:
        claims = self.verifier.verify(self.create_token())
        self.assertEqual(claims["sub"], "subject-1")

    def test_wrong_audience_is_rejected(self) -> None:
        with self.assertRaises(InvalidAccessTokenError):
            self.verifier.verify(self.create_token(aud="another-api"))

    def test_expired_token_is_rejected(self) -> None:
        with self.assertRaises(InvalidAccessTokenError):
            self.verifier.verify(self.create_token(exp=int(time.time()) - 1))


class AuthorizationTests(unittest.TestCase):
    def test_principal_uses_standard_keycloak_client_roles(self) -> None:
        principal = principal_from_claims(
            {
                "sub": "subject-1",
                "preferred_username": "employee-a",
                "resource_access": {
                    settings.keycloak_client_id: {
                        "roles": [settings.keycloak_user_role],
                    }
                },
            }
        )

        self.assertEqual(principal.subject_id, "subject-1")
        self.assertEqual(principal.roles, [settings.keycloak_user_role])
        self.assertEqual(principal.allowed_ips, [])

    def test_bearer_access_token_is_converted_to_principal(self) -> None:
        claims = {
            "sub": "subject-1",
            "preferred_username": "employee-a",
            "resource_access": {
                settings.keycloak_client_id: {
                    "roles": [settings.keycloak_user_role],
                }
            },
        }
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="signed-access-token",
        )

        with patch("api.auth.token_verifier.verify", return_value=claims):
            principal = get_principal(credentials)

        self.assertEqual(principal.subject_id, "subject-1")
        self.assertEqual(principal.auth_type, "keycloak_bearer")

    def test_offline_api_key_is_converted_to_keycloak_user_principal(self) -> None:
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="sk-offline-token-value-with-enough-random-data",
        )
        record = {"key_id": "offline-key-id"}
        claims = {
            "sub": "human-user-subject",
            "preferred_username": "employee-a",
            "azp": settings.keycloak_offline_client_id,
            "resource_access": {
                settings.keycloak_client_id: {
                    "roles": [settings.keycloak_user_role],
                }
            },
        }
        with patch(
            "api.auth.offline_api_key_service.authenticate",
            return_value=(record, claims),
        ), patch(
            "api.auth.permission_storage.get_subject_permissions",
            return_value=["firewall.allow"],
        ), patch(
            "api.auth.permission_storage.get_subject_allowed_ips",
            return_value=["192.168.5.224"],
        ), patch(
            "api.auth.permission_storage.get_managed_user",
            return_value={"enabled": True},
        ):
            principal = authenticate_request(credentials)

        self.assertEqual(principal.subject_id, "human-user-subject")
        self.assertEqual(principal.auth_type, "offline_api_key")
        self.assertEqual(principal.key_id, "offline-key-id")
        self.assertEqual(principal.permissions, ["firewall.allow"])

    def test_user_secret_key_is_rejected_by_default(self) -> None:
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="sk1.0123456789abcdef0123456789abcdef.secret",
        )

        with self.assertRaises(HTTPException) as caught:
            authenticate_request(credentials)

        self.assertEqual(caught.exception.status_code, 401)
        self.assertIn("disabled", str(caught.exception.detail))

    def test_user_secret_key_compatibility_can_be_enabled(self) -> None:
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="sk1.0123456789abcdef0123456789abcdef.secret",
        )
        user = {
            "subject_id": "human-user-subject",
            "username": "employee-a",
            "enabled": True,
        }
        record = {"key_id": "0123456789abcdef0123456789abcdef"}
        with patch.object(
            settings,
            "legacy_user_secret_key_auth_enabled",
            True,
        ), patch(
            "api.auth.user_secret_key_service.verify",
            return_value=(record, user),
        ), patch(
            "api.auth.permission_storage.get_subject_permissions",
            return_value=["firewall.allow"],
        ), patch(
            "api.auth.permission_storage.get_subject_allowed_ips",
            return_value=["192.168.5.224"],
        ):
            principal = authenticate_request(credentials)

        self.assertEqual(principal.subject_id, "human-user-subject")
        self.assertEqual(principal.auth_type, "user_secret_key")
        self.assertEqual(principal.key_id, record["key_id"])
        self.assertEqual(principal.permissions, ["firewall.allow"])
        self.assertEqual(principal.allowed_ips, ["192.168.5.224"])

        with self.assertRaises(HTTPException) as caught:
            require_trade_access_admin(principal)
        self.assertEqual(caught.exception.status_code, 403)

    def test_permissions_are_loaded_by_stable_token_subject(self) -> None:
        claims = {
            "sub": "human-user-subject",
            "azp": settings.keycloak_browser_client_id,
            "preferred_username": "employee-a",
            "resource_access": {
                settings.keycloak_client_id: {
                    "roles": [settings.keycloak_user_role],
                }
            },
        }
        credentials = HTTPAuthorizationCredentials(
            scheme="Bearer",
            credentials="signed-access-token",
        )
        with patch("api.auth.token_verifier.verify", return_value=claims), patch(
            "api.auth.permission_storage.get_subject_permissions",
            return_value=["firewall.allow"],
        ), patch(
            "api.auth.permission_storage.get_subject_allowed_ips",
            return_value=["192.168.5.224"],
        ), patch(
            "api.auth.permission_storage.get_managed_user",
            return_value={"enabled": True},
        ):
            principal = authenticate_request(credentials)

        self.assertEqual(principal.subject_id, "human-user-subject")
        self.assertEqual(principal.client_id, settings.keycloak_browser_client_id)
        self.assertEqual(principal.subject_type, "user")
        self.assertEqual(principal.auth_type, "keycloak_bearer")
        self.assertEqual(principal.permissions, ["firewall.allow"])
        self.assertEqual(principal.allowed_ips, ["192.168.5.224"])

    def test_trade_access_admin_portal_token_is_mapped_to_admin_principal(self) -> None:
        claims = {
            "sub": "trade-admin-subject",
            "preferred_username": "trade-admin",
            "azp": settings.keycloak_admin_browser_client_id,
            "resource_access": {
                settings.keycloak_client_id: {
                    "roles": [settings.keycloak_admin_role],
                }
            },
        }
        with patch(
            "api.auth.permission_storage.get_subject_permissions",
            return_value=["identity.user.manage"],
        ), patch(
            "api.auth.permission_storage.get_subject_allowed_ips",
            return_value=[],
        ), patch(
            "api.auth.permission_storage.get_managed_user",
            return_value={"enabled": True},
        ):
            principal = principal_from_claims(claims)

        self.assertEqual(principal.auth_type, "keycloak_admin_bearer")
        self.assertTrue(principal.is_admin)
        self.assertEqual(require_trade_access_admin(principal), principal)

    def test_regular_portal_token_cannot_access_management_api(self) -> None:
        principal = admin_principal().model_copy(
            update={
                "auth_type": "keycloak_bearer",
                "client_id": settings.keycloak_browser_client_id,
            }
        )
        with self.assertRaises(HTTPException) as caught:
            require_trade_access_admin(principal)
        self.assertEqual(caught.exception.status_code, 403)

    def test_admin_portal_user_without_admin_role_is_rejected(self) -> None:
        principal = user_principal().model_copy(
            update={
                "auth_type": "keycloak_admin_bearer",
                "client_id": settings.keycloak_admin_browser_client_id,
            }
        )
        with self.assertRaises(HTTPException) as caught:
            require_trade_access_admin(principal)
        self.assertEqual(caught.exception.status_code, 403)

    def test_missing_bearer_token_is_rejected(self) -> None:
        with self.assertRaises(HTTPException) as caught:
            authenticate_request(None)
        self.assertEqual(caught.exception.status_code, 401)

    def test_user_and_admin_roles_are_checked_at_endpoint_boundary(self) -> None:
        self.assertEqual(require_trade_access_user(user_principal()).subject_id, "user-subject")
        self.assertEqual(require_trade_access_user(admin_principal()).subject_id, "admin-subject")
        self.assertEqual(require_trade_access_admin(admin_principal()).subject_id, "admin-subject")

        with self.assertRaises(HTTPException) as caught:
            require_trade_access_admin(user_principal())
        self.assertEqual(caught.exception.status_code, 403)

    def test_operation_permission_is_checked_at_endpoint_boundary(self) -> None:
        allowed = user_principal()
        self.assertEqual(require_firewall_allow(allowed).subject_id, "user-subject")

        denied = allowed.model_copy(update={"permissions": ["firewall.job.read"]})
        with self.assertRaises(HTTPException) as caught:
            require_firewall_allow(denied)
        self.assertEqual(caught.exception.status_code, 403)

    def test_split_operation_permissions_are_checked_at_endpoint_boundary(self) -> None:
        principal = user_principal().model_copy(
            update={
                "permissions": [
                    "firewall.ip.allow",
                    "firewall.ports.allow",
                    "firewall.ports.deny",
                    "firewall.ip.deny",
                ]
            }
        )

        self.assertEqual(require_firewall_allow(principal), principal)
        self.assertEqual(require_firewall_deny(principal), principal)
        self.assertEqual(require_firewall_ip_allow(principal), principal)
        self.assertEqual(require_firewall_ports_allow(principal), principal)
        self.assertEqual(require_firewall_ports_deny(principal), principal)
        self.assertEqual(require_firewall_ip_deny(principal), principal)

        missing_ip_deny = principal.model_copy(
            update={"permissions": ["firewall.ports.deny"]}
        )
        with self.assertRaises(HTTPException) as caught:
            require_firewall_deny(missing_ip_deny)
        self.assertEqual(caught.exception.status_code, 403)

    def test_user_management_requires_admin_role_and_permission(self) -> None:
        self.assertEqual(
            require_identity_user_manage(admin_principal()).subject_id,
            "admin-subject",
        )
        with self.assertRaises(HTTPException) as caught:
            require_trade_access_admin(user_principal())
        self.assertEqual(caught.exception.status_code, 403)

        admin_without_permission = admin_principal().model_copy(
            update={"permissions": ["firewall.job.audit"]}
        )
        with self.assertRaises(HTTPException) as caught:
            require_identity_user_manage(admin_without_permission)
        self.assertEqual(caught.exception.status_code, 403)

    def test_user_may_only_submit_an_assigned_single_ip(self) -> None:
        authorize_trade_access_request(
            user_principal(),
            TradeAccessJobCreate(
                action="allow",
                target_ip="192.168.66.22",
                ports=[22, 65535],
            ),
        )

        with self.assertRaises(HTTPException) as caught:
            authorize_trade_access_request(
                user_principal(),
                TradeAccessJobCreate(
                    action="allow",
                    target_ip="192.168.66.23",
                    ports=[443],
                ),
            )
        self.assertEqual(caught.exception.status_code, 403)

        with self.assertRaises(HTTPException) as caught:
            authorize_trade_access_request(
                user_principal(),
                TradeAccessJobCreate(
                    action="deny",
                    target_ip="192.168.66.0",
                    mask=24,
                ),
            )
        self.assertEqual(caught.exception.status_code, 403)

    def test_public_action_endpoints_do_not_accept_action_or_wrong_port_shape(self) -> None:
        with self.assertRaises(ValidationError):
            TradeAccessAllowRequest.model_validate(
                {
                    "action": "deny",
                    "target_ip": "192.168.66.22",
                    "ports": [12001],
                }
            )

        with self.assertRaises(ValidationError):
            TradeAccessDenyRequest.model_validate(
                {
                    "target_ip": "192.168.66.22",
                    "ports": [12001],
                }
            )

        with self.assertRaises(ValidationError):
            TradeAccessPortDenyRequest.model_validate(
                {
                    "target_ip": "192.168.66.22",
                }
            )

    def test_admin_may_submit_a_network_target(self) -> None:
        authorize_trade_access_request(
            admin_principal(),
            TradeAccessJobCreate(
                action="deny",
                target_ip="192.168.66.0",
                mask=24,
            ),
        )

    def test_job_ownership_uses_stable_keycloak_subject(self) -> None:
        job = {"principal_id": "user-subject"}
        authorize_job_read(user_principal(), job)

        with self.assertRaises(HTTPException) as caught:
            authorize_job_read(user_principal("another-subject"), job)
        self.assertEqual(caught.exception.status_code, 404)


if __name__ == "__main__":
    unittest.main()
