import re
from pathlib import Path

import yaml
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from api.env_file import load_runtime_environment


load_runtime_environment()


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def load_firewall_orchestration_defaults(
    path: Path | None = None,
) -> dict[str, object]:
    """Load non-secret API/worker orchestration defaults from Ansible all.yml."""
    config_path = path or (project_root() / "group_vars" / "all.yml")
    defaults: dict[str, object] = {
        "firewall_targets": "TEST-FW",
        "firewall_parallel_workers": 3,
        "firewall_child_max_attempts": 2,
        "firewall_reconcile_retry_seconds": 3,
    }
    if not config_path.exists():
        return defaults

    try:
        payload = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ValueError(
            "Failed to parse firewall orchestration config {0}: {1}".format(
                config_path,
                exc,
            )
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError(
            "Ansible group vars root must be a YAML object: {0}".format(
                config_path
            )
        )

    orchestration = payload.get("trade_access_api") or {}
    if not isinstance(orchestration, dict):
        raise ValueError(
            "trade_access_api must be a YAML object in {0}".format(config_path)
        )

    raw_targets = orchestration.get("firewall_targets", defaults["firewall_targets"])
    if isinstance(raw_targets, list):
        if not raw_targets or not all(
            isinstance(item, str) and item.strip() for item in raw_targets
        ):
            raise ValueError(
                "trade_access_api.firewall_targets must contain non-empty strings."
            )
        firewall_targets = ",".join(item.strip() for item in raw_targets)
    elif isinstance(raw_targets, str):
        firewall_targets = raw_targets
    else:
        raise ValueError(
            "trade_access_api.firewall_targets must be a string or YAML list."
        )

    return {
        "firewall_targets": firewall_targets,
        "firewall_parallel_workers": orchestration.get(
            "firewall_parallel_workers",
            defaults["firewall_parallel_workers"],
        ),
        "firewall_child_max_attempts": orchestration.get(
            "firewall_child_max_attempts",
            defaults["firewall_child_max_attempts"],
        ),
        "firewall_reconcile_retry_seconds": orchestration.get(
            "firewall_reconcile_retry_seconds",
            defaults["firewall_reconcile_retry_seconds"],
        ),
    }


FIREWALL_ORCHESTRATION_DEFAULTS = load_firewall_orchestration_defaults()


class Settings(BaseSettings):
    """Runtime settings for the API service."""

    model_config = SettingsConfigDict(
        env_prefix="TRADE_ACCESS_API_",
        extra="ignore",
        validate_default=True,
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
    # Defaults come from group_vars/all.yml:trade_access_api. Existing
    # TRADE_ACCESS_API_* environment variables remain optional overrides.
    firewall_targets: str = str(FIREWALL_ORCHESTRATION_DEFAULTS["firewall_targets"])
    firewall_parallel_workers: int = Field(
        default=FIREWALL_ORCHESTRATION_DEFAULTS["firewall_parallel_workers"],
        ge=1,
        le=16,
    )
    firewall_child_max_attempts: int = Field(
        default=FIREWALL_ORCHESTRATION_DEFAULTS["firewall_child_max_attempts"],
        ge=1,
        le=10,
    )
    firewall_reconcile_retry_seconds: int = Field(
        default=FIREWALL_ORCHESTRATION_DEFAULTS["firewall_reconcile_retry_seconds"],
        ge=1,
        le=3600,
    )
    job_timeout_seconds: float = Field(default=1800, gt=0, le=86400)
    runner_timeout_seconds: float = Field(default=900, gt=0, le=86400)
    snapshot_timeout_seconds: float = Field(default=300, gt=0, le=86400)
    runner_lock_timeout_seconds: float = Field(default=10, gt=0, le=300)
    precheck_max_attempts: int = Field(default=3, ge=1, le=100)
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
    keycloak_jwks_cache_seconds: float = Field(default=300.0, gt=0)
    keycloak_jwks_refresh_min_interval_seconds: float = Field(default=10.0, gt=0)
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
                    "firewall_targets contains an invalid profile code: "
                    "{0}".format(code)
                )
            if code not in codes:
                codes.append(code)
        if not codes:
            raise ValueError("At least one firewall target profile must be configured.")
        return tuple(codes)

settings = Settings()
