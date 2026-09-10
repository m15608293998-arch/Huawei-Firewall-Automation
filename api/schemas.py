import ipaddress
import re
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from api.ip_policy import (
    DIRECT_ACCESS_ALLOW_ACTIONS,
    validate_direct_access_target,
)
from api.time_utils import to_china_time_iso


class AccessAction(str, Enum):
    allow = "allow"
    allow_ip = "allow_ip"
    allow_ports = "allow_ports"
    deny = "deny"
    deny_ports = "deny_ports"
    deny_ip = "deny_ip"


class JobStatus(str, Enum):
    pending = "pending"
    running = "running"
    prechecking = "prechecking"
    applying = "applying"
    verifying = "verifying"
    reconciling = "reconciling"
    successful = "successful"
    failed = "failed"
    manual_intervention_required = "manual_intervention_required"
    canceled = "canceled"


class TradeAccessRequestBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_ip: str
    mask: int = Field(default=32, ge=0, le=32)
    description: str | None = Field(default=None, max_length=160)
    client_request_id: str | None = Field(default=None, max_length=128)

    @field_validator("target_ip")
    @classmethod
    def validate_target_ip(cls, value: str) -> str:
        try:
            ip = ipaddress.IPv4Address(value)
        except ValueError:
            raise ValueError("target_ip must be a valid IPv4 address")
        return str(ip)

    @field_validator("description")
    @classmethod
    def validate_description(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if re.search(r"[\r\n\x00-\x1f\x7f]", value):
            raise ValueError("description must not contain newline or control characters")
        return value.strip()

    @field_validator("client_request_id")
    @classmethod
    def validate_client_request_id(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not re.match(r"^[A-Za-z0-9_.:-]+$", value):
            raise ValueError(
                "client_request_id may only contain letters, numbers, dot, underscore, colon, or hyphen"
            )
        return value

    @model_validator(mode="after")
    def validate_target_network(self):
        try:
            ipaddress.IPv4Network(
                "{0}/{1}".format(self.target_ip, self.mask),
                strict=True,
            )
        except ValueError:
            raise ValueError(
                "target_ip must be the exact network address for mask; use mask 32 for a single IP"
            )
        return self


class TradeAccessPortsRequest(TradeAccessRequestBase):
    ports: list[int] = Field(min_length=1, max_length=256)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: list[int]) -> list[int]:
        invalid = [port for port in value if port < 1 or port > 65535]
        if invalid:
            raise ValueError("ports must contain integers between 1 and 65535")
        return sorted(set(value))


class TradeAccessAllowRequest(TradeAccessPortsRequest):
    @model_validator(mode="after")
    def validate_direct_access_target_ip(self):
        validate_direct_access_target(self.target_ip, self.mask)
        return self


class TradeAccessIpAllowRequest(TradeAccessRequestBase):
    @model_validator(mode="after")
    def validate_direct_access_target_ip(self):
        validate_direct_access_target(self.target_ip, self.mask)
        return self


class TradeAccessIpRequest(TradeAccessRequestBase):
    pass


class TradeAccessPortAllowRequest(TradeAccessAllowRequest):
    pass


class TradeAccessPortDenyRequest(TradeAccessPortsRequest):
    pass


class TradeAccessDenyRequest(TradeAccessRequestBase):
    pass


class TradeAccessJobCreate(TradeAccessRequestBase):
    action: AccessAction
    ports: list[int] | None = None

    @model_validator(mode="after")
    def validate_action_payload(self):
        port_actions = {
            AccessAction.allow,
            AccessAction.allow_ports,
            AccessAction.deny_ports,
        }
        no_port_actions = {
            AccessAction.allow_ip,
            AccessAction.deny,
            AccessAction.deny_ip,
        }
        if self.action in port_actions and not self.ports:
            raise ValueError("ports is required and must not be empty for this action")
        if self.action in no_port_actions and self.ports is not None:
            raise ValueError("ports must be omitted for this action")
        if self.action.value in DIRECT_ACCESS_ALLOW_ACTIONS:
            validate_direct_access_target(self.target_ip, self.mask)
        return self


class JobCreateResponse(BaseModel):
    job_id: str
    status: JobStatus
    action: AccessAction
    target_ip: str
    ports: list[int] | None = None
    client_request_id: str | None = None
    firewall_targets: list[str] = Field(default_factory=list)


class FirewallTargetResponse(BaseModel):
    firewall_code: str
    status: str
    attempt_count: int = 0
    runner_status: str | None = None
    runner_rc: int | None = None
    error_message: str | None = None
    before_state: dict[str, object] | None = None
    desired_state: dict[str, object] | None = None
    observed_state: dict[str, object] | None = None
    artifact_dir: str | None = None
    local_tmp_dir: str | None = None
    started_at: str | None = None
    finished_at: str | None = None

    @field_validator("started_at", "finished_at", mode="before")
    @classmethod
    def serialize_target_time(cls, value: str | None) -> str | None:
        return to_china_time_iso(value)


class JobDetailResponse(BaseModel):
    job_id: str
    status: JobStatus
    action: AccessAction
    target_ip: str
    mask: int
    ports: list[int] = Field(default_factory=list)
    description: str | None = None
    client_request_id: str | None = None
    principal_subject: str | None = None
    principal_id: str | None = None
    principal_client_id: str | None = None
    principal_key_id: str | None = None
    principal_type: str | None = None
    auth_type: str | None = None
    permission_code: str | None = None
    runner_status: str | None = None
    runner_rc: int | None = None
    error_message: str | None = None
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    artifact_dir: str | None = None
    local_tmp_dir: str | None = None
    firewall_targets: list[str] = Field(default_factory=list)
    desired_state: dict[str, object] | None = None
    state_version: int | None = None
    next_attempt_at: str | None = None
    target_results: list[FirewallTargetResponse] = Field(default_factory=list)

    @field_validator(
        "created_at",
        "started_at",
        "finished_at",
        "next_attempt_at",
        mode="before",
    )
    @classmethod
    def serialize_job_time_as_china_standard_time(
        cls,
        value: str | None,
    ) -> str | None:
        return to_china_time_iso(value)


class JobEvent(BaseModel):
    firewall_code: str | None = None
    counter: int | None = None
    event: str | None = None
    task: str | None = None
    message: str | None = None
    created: str | None = None


class JobEventsResponse(BaseModel):
    job_id: str
    events: list[JobEvent]


class FirewallIpSnapshotItem(BaseModel):
    ip: str


class FirewallPortSnapshotItem(BaseModel):
    ip: str
    port: int


class FirewallSnapshotResponse(BaseModel):
    generated_at: str
    items: list[FirewallPortSnapshotItem]
    consistency_status: str = "consistent"
    firewall_codes: list[str] = Field(default_factory=list)
    firewalls: dict[str, dict[str, object]] = Field(default_factory=dict)


class FirewallIpSnapshotResponse(BaseModel):
    generated_at: str
    items: list[FirewallIpSnapshotItem]
    consistency_status: str = "consistent"
    firewall_codes: list[str] = Field(default_factory=list)
    firewalls: dict[str, dict[str, object]] = Field(default_factory=dict)


class FirewallPortSnapshotResponse(BaseModel):
    generated_at: str
    items: list[FirewallPortSnapshotItem]
    consistency_status: str = "consistent"
    firewall_codes: list[str] = Field(default_factory=list)
    firewalls: dict[str, dict[str, object]] = Field(default_factory=dict)


class FirewallCheckAction(BaseModel):
    firewall_code: str
    action: str
    ip: str
    port: int | None = None
    present_on_firewalls: list[str] = Field(default_factory=list)
    absent_on_firewalls: list[str] = Field(default_factory=list)
    reason: str


class FirewallCheckIpDifference(BaseModel):
    ip: str
    present_on_firewalls: list[str] = Field(default_factory=list)
    absent_on_firewalls: list[str] = Field(default_factory=list)
    reference_state: str


class FirewallCheckPortDifference(FirewallCheckIpDifference):
    port: int


class FirewallCheckDifferences(BaseModel):
    ips: list[FirewallCheckIpDifference] = Field(default_factory=list)
    ports: list[FirewallCheckPortDifference] = Field(default_factory=list)


class FirewallCheckNodeResponse(BaseModel):
    query_status: str
    generated_at: str | None = None
    artifact_dir: str
    ip_count: int = 0
    port_count: int = 0
    error_message: str | None = None
    ip_missing: list[FirewallIpSnapshotItem] = Field(default_factory=list)
    ip_extra: list[FirewallIpSnapshotItem] = Field(default_factory=list)
    port_missing: list[FirewallPortSnapshotItem] = Field(default_factory=list)
    port_extra: list[FirewallPortSnapshotItem] = Field(default_factory=list)
    suggested_actions: list[FirewallCheckAction] = Field(default_factory=list)


class FirewallCheckSummary(BaseModel):
    configured_firewall_count: int
    successful_firewall_count: int
    ip_consistent: bool | None
    port_consistent: bool | None
    ip_drift_item_count: int
    port_drift_item_count: int
    suggested_action_count: int
    ambiguous_item_count: int


class FirewallConsistencyCheckResponse(BaseModel):
    checked_at: str
    overall_status: str
    reference_strategy: str
    firewall_codes: list[str] = Field(default_factory=list)
    summary: FirewallCheckSummary
    firewalls: dict[str, FirewallCheckNodeResponse] = Field(default_factory=dict)
    differences: FirewallCheckDifferences
    warning: str


class CurrentAccessResponse(BaseModel):
    subject_id: str
    subject: str
    subject_type: str
    client_id: str | None = None
    roles: list[str]
    permissions: list[str]
    allowed_ips: list[str]
    is_admin: bool


class OfflineApiKeyAuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=120)

    @field_validator("label")
    @classmethod
    def normalize_label(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("label must not be empty")
        return normalized


class OfflineApiKeyAuthorizeResponse(BaseModel):
    authorization_url: str
    expires_at: str


class OfflineApiKeyUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=120)

    @field_validator("label")
    @classmethod
    def normalize_label(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("label must not be empty")
        return normalized


class OfflineApiKeyResponse(BaseModel):
    key_id: str
    subject_id: str
    label: str
    key_hint: str
    created_at: str
    last_used_at: str | None = None
    revoked_at: str | None = None


class UserProfile(str, Enum):
    user = "user"
    admin = "admin"


class KeycloakUserSummary(BaseModel):
    subject_id: str
    username: str
    display_name: str | None = None
    email: str | None = None
    enabled: bool


class ManagedUserUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=255)
    display_name: str | None = Field(default=None, max_length=160)
    profile: UserProfile = UserProfile.user
    permissions: list[str] | None = None
    allowed_ips: list[str] = Field(default_factory=list, max_length=256)
    enabled: bool = True

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("username must not be empty")
        return normalized

    @field_validator("display_name")
    @classmethod
    def normalize_user_display_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @field_validator("allowed_ips")
    @classmethod
    def validate_user_allowed_ips(cls, values: list[str]) -> list[str]:
        result = set()
        for value in values:
            try:
                result.add(str(ipaddress.IPv4Address(value)))
            except ValueError:
                raise ValueError("allowed_ips must contain exact IPv4 addresses")
        return sorted(result)


class ManagedUserResponse(BaseModel):
    subject_id: str
    username: str
    display_name: str | None = None
    profile: UserProfile
    enabled: bool
    permissions: list[str]
    allowed_ips: list[str]
    created_at: str
    updated_at: str


class OidcBrowserConfigResponse(BaseModel):
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    logout_endpoint: str
    client_id: str
    scope: str
