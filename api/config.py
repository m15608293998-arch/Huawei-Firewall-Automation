import re
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from api.env_file import load_runtime_environment


load_runtime_environment()


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    """Runtime settings for the API service."""

    model_config = SettingsConfigDict(
        env_prefix="TRADE_ACCESS_API_",
        extra="ignore",
    )

    project_root: Path = Field(default_factory=project_root)
    playbook_path: str = "playbooks/trade_server_access.yml"
    runner_private_data_dir: Path = Field(
        default_factory=lambda: project_root() / ".runtime" / "runner"
    )
    job_tmp_root: Path = Field(default_factory=lambda: project_root() / ".runtime" / "jobs")
    database_path: Path = Field(
        default_factory=lambda: project_root() / ".runtime" / "api" / "jobs.sqlite3"
    )
    # Logical profile codes executed by every mutation parent job.  Test uses a
    # single profile; production enables all three profiles via one env value.
    firewall_targets: str = "TEST-FW"
    firewall_parallel_workers: int = Field(default=3, ge=1, le=16)
    firewall_child_max_attempts: int = Field(default=2, ge=1, le=10)
    auth_enabled: bool = True
    development_subject: str = "api-placeholder"
    keycloak_server_url: str = "http://127.0.0.1:8080"
    keycloak_realm: str = "trade-access"
    keycloak_client_id: str = "trade-access-api"
    keycloak_browser_client_id: str = "trade-access-portal"
    keycloak_browser_scope: str = "openid profile email"
    keycloak_admin_browser_client_id: str = "trade-access-admin-portal"
    keycloak_admin_browser_scope: str = "openid profile email"
    keycloak_offline_client_id: str = "trade-access-offline"
    keycloak_offline_client_secret: str | None = None
    keycloak_offline_scope: str = "openid profile offline_access"
    offline_api_key_token_encryption_key: str | None = None
    keycloak_user_role: str = "trade-access-user"
    keycloak_admin_role: str = "trade-access-admin"
    keycloak_http_timeout_seconds: float = 5.0
    keycloak_jwks_cache_seconds: float = 300.0
    keycloak_ca_cert: str | None = None
    keycloak_admin_client_id: str | None = None
    keycloak_admin_client_secret: str | None = None
    offline_api_key_authorization_ttl_seconds: int = 300
    offline_api_key_max_per_user: int = 5

    @property
    def keycloak_issuer(self) -> str:
        return "{0}/realms/{1}".format(
            self.keycloak_server_url.rstrip("/"),
            self.keycloak_realm,
        )

    @property
    def keycloak_jwks_url(self) -> str:
        return "{0}/protocol/openid-connect/certs".format(self.keycloak_issuer)

    @property
    def keycloak_token_url(self) -> str:
        return "{0}/protocol/openid-connect/token".format(self.keycloak_issuer)

    @property
    def keycloak_authorization_url(self) -> str:
        return "{0}/protocol/openid-connect/auth".format(self.keycloak_issuer)

    @property
    def keycloak_logout_url(self) -> str:
        return "{0}/protocol/openid-connect/logout".format(self.keycloak_issuer)

    @property
    def keycloak_admin_api_url(self) -> str:
        return "{0}/admin/realms/{1}".format(
            self.keycloak_server_url.rstrip("/"),
            self.keycloak_realm,
        )

    @property
    def firewall_target_codes(self) -> tuple[str, ...]:
        codes: list[str] = []
        for raw_code in self.firewall_targets.split(","):
            code = raw_code.strip()
            if not code:
                continue
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", code):
                raise ValueError(
                    "TRADE_ACCESS_API_FIREWALL_TARGETS contains an invalid profile code: "
                    "{0}".format(code)
                )
            if code not in codes:
                codes.append(code)
        if not codes:
            raise ValueError("At least one firewall target profile must be configured.")
        return tuple(codes)

settings = Settings()
