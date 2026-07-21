import threading
import time
from typing import Any, Callable
from urllib.parse import quote

import httpx


class KeycloakAdminConfigurationError(RuntimeError):
    pass


class KeycloakAdminError(RuntimeError):
    pass


class KeycloakAdminClient:
    def __init__(
        self,
        token_url: str,
        admin_api_url: str,
        admin_client_id: str | None,
        admin_client_secret: str | None,
        resource_client_id: str,
        user_role: str,
        admin_role: str,
        timeout_seconds: float = 5.0,
        ca_cert: str | None = None,
        requester: Callable[..., httpx.Response] | None = None,
    ) -> None:
        self.token_url = token_url
        self.admin_api_url = admin_api_url.rstrip("/")
        self.admin_client_id = admin_client_id
        self.admin_client_secret = admin_client_secret
        self.resource_client_id = resource_client_id
        self.user_role = user_role
        self.admin_role = admin_role
        self.timeout_seconds = timeout_seconds
        self.ca_cert = ca_cert
        self.requester = requester or httpx.request
        self._access_token: str | None = None
        self._token_usable_until = 0.0
        self._resource_client_uuid: str | None = None
        self._lock = threading.Lock()

    @property
    def configured(self) -> bool:
        return bool(self.admin_client_id and self.admin_client_secret)

    def get_client_uuid(self, client_id: str) -> str:
        response = self._admin_request(
            "GET",
            "/clients",
            params={"clientId": client_id},
        )
        self._require_status(response, {200}, "find Keycloak client")
        payload = self._json(response, "find Keycloak client")
        if not isinstance(payload, list):
            raise KeycloakAdminError("Keycloak client lookup response is invalid.")
        for item in payload:
            if isinstance(item, dict) and item.get("clientId") == client_id:
                client_uuid = item.get("id")
                if isinstance(client_uuid, str) and client_uuid:
                    return client_uuid
        raise KeycloakAdminError("Keycloak client was not found.")

    def set_user_profile(self, subject_id: str, profile: str | None) -> None:
        desired_role = None
        if profile is not None:
            desired_role = self.admin_role if profile == "admin" else self.user_role
        resource_uuid = self._get_resource_client_uuid()
        desired = (
            self._get_client_role(resource_uuid, desired_role)
            if desired_role is not None
            else None
        )
        managed_role_names = {self.user_role, self.admin_role}
        role_path = "/users/{0}/role-mappings/clients/{1}".format(
            quote(subject_id, safe=""),
            quote(resource_uuid, safe=""),
        )
        current_roles = self._get_role_list(role_path)
        removable = [
            role for role in current_roles if role.get("name") in managed_role_names
        ]
        # 这个系统只管理 user/admin 两个角色，其他 Keycloak 角色不能被误删。
        if removable:
            response = self._admin_request("DELETE", role_path, json=removable)
            self._require_status(response, {204}, "remove old user role")
        if desired is not None:
            response = self._admin_request("POST", role_path, json=[desired])
            self._require_status(response, {204}, "assign user role")

    def search_users(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        response = self._admin_request(
            "GET",
            "/users",
            params={
                "search": query,
                "max": max(1, min(limit, 100)),
                "briefRepresentation": "true",
            },
        )
        self._require_status(response, {200}, "search Keycloak users")
        payload = self._json(response, "search Keycloak users")
        if not isinstance(payload, list):
            raise KeycloakAdminError("Keycloak user search response is invalid.")
        result = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            subject_id = item.get("id")
            username = item.get("username")
            if not isinstance(subject_id, str) or not subject_id:
                continue
            if not isinstance(username, str) or not username:
                continue
            first_name = str(item.get("firstName") or "").strip()
            last_name = str(item.get("lastName") or "").strip()
            display_name = " ".join(part for part in (first_name, last_name) if part)
            result.append(
                {
                    "subject_id": subject_id,
                    "username": username,
                    "display_name": display_name or None,
                    "email": item.get("email"),
                    "enabled": bool(item.get("enabled", True)),
                }
            )
        return result

    def get_user(self, subject_id: str) -> dict[str, Any]:
        response = self._admin_request(
            "GET",
            "/users/{0}".format(quote(subject_id, safe="")),
        )
        self._require_status(response, {200}, "read Keycloak user")
        payload = self._json(response, "read Keycloak user")
        if not isinstance(payload, dict) or payload.get("id") != subject_id:
            raise KeycloakAdminError("Keycloak user response is invalid.")
        return payload

    def _get_resource_client_uuid(self) -> str:
        if self._resource_client_uuid:
            return self._resource_client_uuid
        client_uuid = self.get_client_uuid(self.resource_client_id)
        self._resource_client_uuid = client_uuid
        return client_uuid

    def _get_client_role(self, client_uuid: str, role_name: str) -> dict[str, Any]:
        response = self._admin_request(
            "GET",
            "/clients/{0}/roles/{1}".format(
                quote(client_uuid, safe=""),
                quote(role_name, safe=""),
            ),
        )
        self._require_status(response, {200}, "read Keycloak client role")
        payload = self._json(response, "read Keycloak client role")
        if not isinstance(payload, dict) or not payload.get("id"):
            raise KeycloakAdminError("Keycloak client role response is invalid.")
        return payload

    def _get_role_list(self, path: str) -> list[dict[str, Any]]:
        response = self._admin_request("GET", path)
        self._require_status(response, {200}, "read Keycloak role mappings")
        payload = self._json(response, "read Keycloak role mappings")
        if not isinstance(payload, list):
            raise KeycloakAdminError("Keycloak role mapping response is invalid.")
        return [item for item in payload if isinstance(item, dict)]

    def _admin_request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        base_headers = dict(kwargs.pop("headers", {}))
        verify: bool | str = self.ca_cert or True
        for attempt in range(2):
            token = self._get_admin_token()
            headers = dict(base_headers)
            headers["Authorization"] = "Bearer {0}".format(token)
            try:
                response = self.requester(
                    method,
                    self.admin_api_url + path,
                    headers=headers,
                    timeout=self.timeout_seconds,
                    verify=verify,
                    **kwargs,
                )
            except httpx.HTTPError as exc:
                raise KeycloakAdminError("Unable to reach Keycloak Admin API.") from exc
            if response.status_code != 401 or attempt == 1:
                return response
            # token 可能刚好过期，清缓存后重试一次即可。
            with self._lock:
                self._access_token = None
                self._token_usable_until = 0.0
        raise KeycloakAdminError("Keycloak Admin API authentication failed.")

    def _get_admin_token(self) -> str:
        if not self.configured:
            raise KeycloakAdminConfigurationError(
                "Keycloak provisioning client is not configured."
            )
        now = time.monotonic()
        with self._lock:
            if self._access_token and now < self._token_usable_until:
                return self._access_token

        verify: bool | str = self.ca_cert or True
        try:
            response = self.requester(
                "POST",
                self.token_url,
                auth=(self.admin_client_id, self.admin_client_secret),
                data={"grant_type": "client_credentials"},
                timeout=self.timeout_seconds,
                verify=verify,
            )
        except httpx.HTTPError as exc:
            raise KeycloakAdminError(
                "Unable to reach Keycloak provisioning token endpoint."
            ) from exc
        self._require_status(response, {200}, "authenticate provisioning client")
        payload = self._json(response, "authenticate provisioning client")
        token = payload.get("access_token") if isinstance(payload, dict) else None
        expires_in = payload.get("expires_in", 60) if isinstance(payload, dict) else 60
        if not isinstance(token, str) or not token:
            raise KeycloakAdminError("Provisioning token response is invalid.")
        try:
            usable_for = max(1.0, float(expires_in) - 30.0)
        except (TypeError, ValueError):
            usable_for = 30.0
        with self._lock:
            # 提前 30 秒过期，减少临界点请求拿到 401 的概率。
            self._access_token = token
            self._token_usable_until = time.monotonic() + usable_for
        return token

    @staticmethod
    def _json(response: httpx.Response, operation: str) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise KeycloakAdminError(
                "Keycloak returned invalid JSON while attempting to {0}.".format(
                    operation
                )
            ) from exc

    @staticmethod
    def _require_status(
        response: httpx.Response,
        expected: set[int],
        operation: str,
    ) -> None:
        if response.status_code in expected:
            return
        detail = response.text.strip()
        if len(detail) > 300:
            detail = detail[:300]
        message = "Keycloak failed to {0} (HTTP {1}).".format(
            operation,
            response.status_code,
        )
        if detail:
            message = "{0} {1}".format(message, detail)
        raise KeycloakAdminError(message)
