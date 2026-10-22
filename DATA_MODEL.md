# WorkGuard Data Model

## 1. Design rules

- Store device/policy metadata and security events, not source-code bodies.
- Use UUID primary keys, UTC timestamps, foreign keys and explicit lifecycle states.
- Scope every device, policy, event and exception to an organization/tenant even if the first deployment has only one tenant.
- Use soft-revocation/retention fields only when they serve a defined operational purpose; avoid retaining data indefinitely.
- Avoid sensitive values in JSON metadata. Define allowed event fields and reject unexpected free-form payloads.

## 2. Core entities

### `organizations`
`id`, `name`, `created_at`, `status`.

### `users`
`id`, `organization_id`, `oidc_subject`, `display_name`, `email`, `status`, `created_at`, `last_login_at`.
Use OIDC subject as the stable external identity mapping; do not use email alone as an immutable identity key.

### `role_assignments`
`id`, `organization_id`, `user_id`, `role`, `assigned_by`, `created_at`, `expires_at`.

### `devices`
`id`, `organization_id`, `device_public_id`, `display_name`, `assigned_user_id`, `platform`, `os_version`, `os_edition`, `agent_version`, `status`, `enrolled_at`, `last_seen_at`, `revoked_at`.
Never store private device credential material in this table.

### `device_credentials`
`id`, `device_id`, `credential_thumbprint`, `issued_at`, `expires_at`, `revoked_at`, `last_used_at`.
Private keys should remain in OS-protected storage or approved hardware-backed key storage. The server stores public/certificate metadata and revocation state.

### `policies`
`id`, `organization_id`, `name`, `description`, `risk_level`, `schema_version`, `lifecycle_state`, `created_by`, `created_at`, `updated_at`.

### `policy_versions`
`id`, `policy_id`, `version`, `canonical_digest`, `signed_artifact_ref`, `signature_key_id`, `issued_at`, `expires_at`, `created_by`, `approved_by`, `published_at`, `rollback_of_version`.
Policy artifact references point to the signed configuration, not source files. Enforce uniqueness on `(policy_id, version)`.

### `policy_assignments`
`id`, `policy_version_id`, `target_type`, `target_id`, `priority`, `created_by`, `created_at`, `expires_at`.
Define deterministic conflict/precedence semantics and validate assignments before publish.

### `control_results`
`id`, `device_id`, `policy_version_id`, `control_id`, `status`, `desired_state`, `observed_state`, `provider`, `observed_at`, `error_code`, `safe_details`.
Do not store full command lines or secrets. Use typed/validated data rather than arbitrary command execution output.

### `security_events`
`id`, `organization_id`, `device_id`, `event_type`, `severity`, `source`, `occurred_at`, `received_at`, `correlation_id`, `safe_metadata`, `response_state`.
Use append-oriented access; high-integrity audit copies should be shipped to protected storage where feasible.

### `exceptions`
`id`, `organization_id`, `control_id`, `target_type`, `target_id`, `reason`, `requested_by`, `approved_by`, `created_at`, `starts_at`, `expires_at`, `revoked_at`, `compensating_control`.
Require expiry and a reason. Permanent exceptions need an explicit risk acceptance workflow if permitted at all.

### `admin_audit_events`
`id`, `organization_id`, `actor_user_id`, `action`, `target_type`, `target_id`, `reason`, `request_id`, `occurred_at`, `safe_metadata`, `previous_digest`, `event_digest`.
A hash chain can help detect modification but does not by itself make a database immutable. Copy to access-controlled append-only storage for stronger assurance.

### `agent_releases`
`id`, `version`, `platform`, `artifact_digest`, `signature_ref`, `release_channel`, `minimum_version`, `published_at`, `revoked_at`.

## 3. Retention proposal

This is a proposal requiring company/legal approval, not legal advice:
- Heartbeats and latest status: maintain current device state; keep historical status changes for a limited period (for example, 90 days).
- Routine security events: 90–180 days initially, adjusted to response needs and policy.
- Administrator and policy audit events: 180–365 days or company-approved period.
- Enrollment codes: delete immediately after use/expiry; store only a hash while valid.
- No source-code contents or unrelated personal files are retained by WorkGuard.

Document the purpose and exact retention for each category before employee rollout.
