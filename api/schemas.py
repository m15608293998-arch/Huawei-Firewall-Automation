import ipaddress
import re
from enum import Enum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    field_validator,
    model_validator,
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
    successful = "successful"
    failed = "failed"
    canceled = "canceled"


class TradeAccessRequestBase(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_ip: str
    mask: StrictInt = Field(default=32, ge=0, le=32)
    description: str | None = Field(default=None, max_length=160)

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
    ports: list[StrictInt] = Field(min_length=1, max_length=256)

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, value: list[int]) -> list[int]:
        invalid = [port for port in value if port < 1 or port > 65535]
        if invalid:
            raise ValueError("ports must contain integers between 1 and 65535")
        return sorted(set(value))


class TradeAccessAllowRequest(TradeAccessPortsRequest):
    pass


class TradeAccessIpRequest(TradeAccessRequestBase):
    pass


class TradeAccessPortAllowRequest(TradeAccessPortsRequest):
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
        return self


class JobCreateResponse(BaseModel):
    job_id: str
    status: JobStatus
    action: AccessAction
    target_ip: str
    ports: list[int] | None = None


class JobDetailResponse(BaseModel):
    job_id: str
    status: JobStatus
    action: AccessAction
    target_ip: str
    mask: int
    ports: list[int] = Field(default_factory=list)
    description: str | None = None
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

    @field_validator("created_at", "started_at", "finished_at", mode="before")
    @classmethod
    def serialize_job_time_as_china_standard_time(
        cls,
        value: str | None,
    ) -> str | None:
        return to_china_time_iso(value)


class JobEvent(BaseModel):
    counter: int | None = None
    event: str | None = None
    task: str | None = None
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


class FirewallIpSnapshotResponse(BaseModel):
    generated_at: str
    items: list[FirewallIpSnapshotItem]


class FirewallPortSnapshotResponse(BaseModel):
    generated_at: str
    items: list[FirewallPortSnapshotItem]


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
