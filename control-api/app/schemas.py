from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class HealthResponse(BaseModel):
    status: str


class DeviceSummary(BaseModel):
    id: str
    org_id: str = "org-default"
    display_name: str
    assigned_user_id: str | None = None
    os_version: str
    os_edition: str = "Windows 11 Enterprise"
    agent_version: str
    status: Literal["enrolled", "compliant", "noncompliant", "stale", "revoked", "unknown"]
    last_seen_at: str | None = None
    policy_version_desired: int | None = None
    policy_version_observed: int | None = None
    last_applied_version: int | None = None


class ControlResult(BaseModel):
    control_id: str
    status: Literal["enforced", "partial", "failed", "unsupported", "not_configured", "unknown"]
    provider: str
    provider_version: str | None = None
    observed_at: str
    error_code: str | None = None
    safe_details: str | None = None


class DeviceDetail(DeviceSummary):
    controls: list[ControlResult] = Field(default_factory=list)
    assigned_policy_id: str | None = None
    compliance_details: list[dict[str, Any]] = Field(default_factory=list)


class CreateEnrollmentCodeRequest(BaseModel):
    expires_in_seconds: int = Field(default=300, ge=60, le=600)
    requested_for_user_id: str | None = None
    reason: str = Field(min_length=3, max_length=500)


class EnrollmentCodeResponse(BaseModel):
    enrollment_code: str
    expires_at: str
    requested_for_user_id: str | None = None


class RevokeDeviceRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class RotateDeviceCredentialResponse(BaseModel):
    device_id: str
    device_token: str
    issued_at: str


class PolicyControlItem(BaseModel):
    control_id: Literal[
        "removable_storage",
        "application_control",
        "disk_encryption",
        "endpoint_protection",
        "endpoint_dlp",
        "network_policy",
    ]
    required: bool
    settings: dict[str, Any]


class PolicyObject(BaseModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    policy_id: str
    policy_version: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=120)
    description: str | None = Field(default="", max_length=1000)
    rollout_mode: Literal["audit", "enforce"] = "enforce"
    controls: list[PolicyControlItem]

    @field_validator("controls")
    @classmethod
    def unique_controls(cls, controls: list[PolicyControlItem]) -> list[PolicyControlItem]:
        ids = [control.control_id for control in controls]
        if len(ids) != len(set(ids)):
            raise ValueError("control_id values must be unique")
        return controls


class PolicySummary(BaseModel):
    id: str
    name: str
    lifecycle_state: Literal["draft", "submitted", "approved", "published", "retired"]
    version: int | None = None
    updated_at: str
    created_by: str | None = None
    approved_by: str | None = None
    published_by: str | None = None


class PolicyVersionSummary(BaseModel):
    version: int
    digest_sha256: str
    key_id: str
    rollback_of_version: int | None = None
    published_at: str
    published_by: str
    reason: str | None = None


class PolicyDetail(PolicySummary):
    policy: PolicyObject
    versions: list[PolicyVersionSummary] = Field(default_factory=list)


class CreateDraftPolicyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    policy: PolicyObject
    reason: str = Field(min_length=3, max_length=500)


class EditDraftPolicyRequest(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    policy: PolicyObject | None = None
    reason: str | None = Field(default=None, min_length=3, max_length=500)


class ApprovePolicyRequest(BaseModel):
    approval_notes: str = Field(min_length=3, max_length=500)


class PublishPolicyRequest(BaseModel):
    # The server computes the next immutable version.  A client may echo the
    # expected version for optimistic-concurrency checking.
    version: int | None = Field(default=None, ge=1)
    reason: str = Field(min_length=3, max_length=500)
    rollout_group: str | None = "all"


class RollbackPolicyRequest(BaseModel):
    target_version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=500)


class SignedPolicyEnvelope(BaseModel):
    spec_version: Literal["1"] = "1"
    policy_id: str
    policy_version: int
    schema_version: str = "1.0.0"
    issued_at: str
    expires_at: str
    target_device_id: str
    digest_sha256: str
    key_id: str
    signature: str
    policy: PolicyObject


class SecurityEvent(BaseModel):
    id: str | None = Field(default=None, max_length=64)
    device_id: str | None = None
    event_type: str = Field(min_length=1, max_length=120)
    severity: Literal["info", "low", "medium", "high", "critical"]
    occurred_at: str
    source: str = Field(min_length=1, max_length=120)
    response_state: str = Field(min_length=1, max_length=120)


class AdminAuditEvent(BaseModel):
    id: str
    actor_user_id: str
    action: str
    target_type: str
    target_id: str | None = None
    details: dict[str, Any] | None = None
    created_at: str
    prev_hash: str | None = None
    record_hash: str | None = None


class AuditVerificationResponse(BaseModel):
    valid: bool
    checked: int
    head: str


class AgentEnrollRequest(BaseModel):
    enrollment_code: str = Field(min_length=8, max_length=128)
    device_public_key: str | None = Field(default=None, max_length=4096)
    agent_version: str = Field(min_length=1, max_length=64)
    os_version: str = Field(min_length=1, max_length=200)
    os_edition: str | None = Field(default="Windows 11 Enterprise", max_length=120)


class AgentEnrollResponse(BaseModel):
    device_id: str
    device_token: str
    expires_at: str


class AgentHeartbeatRequest(BaseModel):
    agent_version: str = Field(min_length=1, max_length=64)
    os_version: str = Field(min_length=1, max_length=200)
    os_edition: str | None = Field(default=None, max_length=120)
    current_policy_version: int | None = Field(default=None, ge=0)
    observed_at: str
    endpoint_protection_state: Literal["active", "inactive", "unknown", "unsupported"] | None = "unknown"


class AgentPolicyResultsRequest(BaseModel):
    policy_version: int = Field(ge=1)
    observed_at: str
    controls: list[ControlResult] = Field(min_length=1, max_length=50)


class AgentEventsBatchRequest(BaseModel):
    events: list[SecurityEvent] = Field(min_length=1, max_length=1000)


class AgentUpdatesCheckRequest(BaseModel):
    current_version: str = Field(min_length=1, max_length=64)
    os_version: str = Field(min_length=1, max_length=200)
    architecture: Literal["x64", "arm64"]


class AgentReleaseCheckResponse(BaseModel):
    update_available: bool
    release_version: str | None = None
    artifact_url: str | None = None
    artifact_sha256: str | None = None
    signature_base64: str | None = None
    mandatory: bool = False


class CreateExceptionRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=64)
    control_id: str = Field(min_length=1, max_length=64)
    reason: str = Field(min_length=5, max_length=500)
    expires_at: str


class RevokeExceptionRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)


class ExceptionSummary(BaseModel):
    id: str
    device_id: str
    control_id: str
    reason: str
    status: str
    created_at: str
    expires_at: str
    revoked_at: str | None = None
    revoked_reason: str | None = None
