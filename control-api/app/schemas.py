from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any, Literal
from datetime import datetime

class HealthResponse(BaseModel):
    status: str

class DeviceSummary(BaseModel):
    id: str
    display_name: str
    assigned_user_id: Optional[str] = None
    os_version: str
    agent_version: str
    status: Literal["enrolled", "compliant", "noncompliant", "stale", "revoked", "unknown"]
    last_seen_at: Optional[str] = None

class ControlResult(BaseModel):
    control_id: str
    status: Literal["enforced", "partial", "failed", "unsupported", "not_configured", "unknown"]
    provider: str
    observed_at: str
    error_code: Optional[str] = None
    safe_details: Optional[str] = None

class DeviceDetail(DeviceSummary):
    os_edition: str
    policy_version_desired: Optional[int] = None
    policy_version_observed: Optional[int] = None
    controls: List[ControlResult] = []

class CreateEnrollmentCodeRequest(BaseModel):
    expires_in_seconds: int = Field(default=300, ge=60, le=600)
    requested_for_user_id: Optional[str] = None
    reason: str = Field(min_length=3, max_length=500)

class EnrollmentCodeResponse(BaseModel):
    enrollment_code: str
    expires_at: str

class RevokeDeviceRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)

class PolicyControlItem(BaseModel):
    control_id: Literal[
        "removable_storage",
        "application_control",
        "disk_encryption",
        "endpoint_protection",
        "endpoint_dlp",
        "network_policy"
    ]
    required: bool
    settings: Dict[str, Any]

class PolicyObject(BaseModel):
    schema_version: Literal["1.0.0"] = "1.0.0"
    policy_id: str
    policy_version: int = Field(ge=1)
    name: str = Field(min_length=1, max_length=120)
    description: Optional[str] = Field(default="", max_length=1000)
    rollout_mode: Literal["audit", "enforce"] = "enforce"
    controls: List[PolicyControlItem]

class PolicySummary(BaseModel):
    id: str
    name: str
    lifecycle_state: Literal["draft", "submitted", "approved", "published", "retired"]
    version: Optional[int] = None
    updated_at: str

class PolicyDetail(PolicySummary):
    policy: PolicyObject
    created_by: str
    approved_by: Optional[str] = None
    published_by: Optional[str] = None

class CreateDraftPolicyRequest(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    policy: PolicyObject
    reason: str = Field(min_length=3, max_length=500)

class EditDraftPolicyRequest(BaseModel):
    name: Optional[str] = None
    policy: Optional[PolicyObject] = None
    reason: Optional[str] = None

class ApprovePolicyRequest(BaseModel):
    approval_notes: str = Field(min_length=3, max_length=500)

class PublishPolicyRequest(BaseModel):
    version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=500)
    rollout_group: Optional[str] = "all"

class RollbackPolicyRequest(BaseModel):
    target_version: int = Field(ge=1)
    reason: str = Field(min_length=3, max_length=500)

class SignedPolicyEnvelope(BaseModel):
    policy_id: str
    policy_version: int
    schema_version: str = "1.0.0"
    issued_at: str
    expires_at: str
    target_device_id: str
    digest_sha256: str
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str
    signature: str
    policy: PolicyObject

class SecurityEvent(BaseModel):
    id: str
    device_id: Optional[str] = None
    event_type: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    occurred_at: str
    source: str
    response_state: str

class AdminAuditEvent(BaseModel):
    id: str
    actor_user_id: str
    action: str
    target_type: str
    target_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    created_at: str

class AgentEnrollRequest(BaseModel):
    enrollment_code: str
    device_public_key: str
    agent_version: str
    os_version: str
    os_edition: Optional[str] = "Windows 11 Enterprise"

class AgentEnrollResponse(BaseModel):
    device_id: str
    credential_enrollment_uri: str

class AgentHeartbeatRequest(BaseModel):
    agent_version: str
    os_version: str
    os_edition: Optional[str] = None
    current_policy_version: Optional[int] = None
    observed_at: str
    endpoint_protection_state: Optional[Literal["active", "inactive", "unknown", "unsupported"]] = "active"

class AgentPolicyResultsRequest(BaseModel):
    policy_version: int
    observed_at: str
    controls: List[ControlResult]

class AgentEventsBatchRequest(BaseModel):
    events: List[SecurityEvent]

class AgentUpdatesCheckRequest(BaseModel):
    current_version: str
    os_version: str
    architecture: Literal["x64", "arm64"]

class AgentReleaseCheckResponse(BaseModel):
    update_available: bool
    release_version: Optional[str] = None
    artifact_url: Optional[str] = None
    artifact_sha256: Optional[str] = None
    signature_base64: Optional[str] = None
    mandatory: bool = False
