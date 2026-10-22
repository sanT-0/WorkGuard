# WorkGuard API Contract

**Version:** `v1` (draft)

The machine-readable starter contract is in [`openapi.yaml`](openapi.yaml). The routes below are a design contract, not a deployed API.

## 1. API conventions

- Base path: `/api/v1`
- JSON request/response, UTF-8.
- TLS required; reject cleartext except in a local development environment.
- Interactive admin calls use OIDC bearer tokens. Agent endpoints use device-bound credentials (prefer mTLS or short-lived device tokens bound to client certificates).
- All timestamps are RFC 3339 UTC.
- All IDs are UUIDs.
- List endpoints use cursor pagination. Set limits, with default `50` and maximum `200`.
- Mutating admin requests accept `Idempotency-Key` where retries could create duplicate actions.
- Return an opaque `request_id` on every error. Never return stack traces or secrets.
- Version APIs and policy schemas independently.

## 2. Roles

- `security_admin`: manage device enrolment, policies, approvals and exceptions.
- `it_operator`: read devices, trigger sync and triage supported remediation operations; cannot approve/publish high-impact policies alone.
- `auditor`: read-only policy, device status and audit events.
- `agent`: access only its own identity, assignments, event upload and policy result endpoints.

Enforce roles and object scope server-side. An agent cannot supply a device ID to read or mutate another device's data.

## 3. Administrator routes

| Method | Path | Purpose | Access |
|---|---|---|---|
| `GET` | `/health/live` | Process liveness only | internal/monitoring |
| `GET` | `/health/ready` | Dependency readiness without secrets | internal/monitoring |
| `GET` | `/admin/devices` | Search/filter devices | operator+ |
| `GET` | `/admin/devices/{device_id}` | Device detail and verified control status | operator+ |
| `POST` | `/admin/enrollment-codes` | Create short-lived single-use enrollment code | security_admin |
| `POST` | `/admin/devices/{device_id}/revoke` | Revoke device credential/sensitive access | security_admin; reason required |
| `GET` | `/admin/policies` | List policies and lifecycle state | operator+ |
| `POST` | `/admin/policies` | Create draft from schema/template | security_admin |
| `GET` | `/admin/policies/{policy_id}` | Policy details and rollout status | operator+ |
| `PATCH` | `/admin/policies/{policy_id}` | Edit draft only; require ETag/version | security_admin |
| `POST` | `/admin/policies/{policy_id}/submit` | Submit draft for review | security_admin |
| `POST` | `/admin/policies/{policy_id}/approve` | Approve policy as second user | authorized approver distinct from author |
| `POST` | `/admin/policies/{policy_id}/publish` | Publish signed policy | release permission after approval |
| `POST` | `/admin/policies/{policy_id}/rollback` | Publish prior approved policy version | security_admin; reason required |
| `GET` | `/admin/events` | Search security events | auditor+ |
| `GET` | `/admin/audit-events` | Search administrator audit trail | auditor+ |
| `POST` | `/admin/exceptions` | Request/create scoped exception | per approval rules |
| `POST` | `/admin/exceptions/{exception_id}/revoke` | Revoke exception | security_admin |

## 4. Agent routes

| Method | Path | Purpose | Notes |
|---|---|---|---|
| `POST` | `/agent/enroll` | Exchange a one-time enrollment code for device identity | Rate limited; code is single-use; no reusable shared secret |
| `POST` | `/agent/heartbeat` | Report liveness, OS/agent versions and policy version | Metadata only |
| `GET` | `/agent/policies/current` | Get policy assignment for authenticated device | Response includes version, expiry, digest/signature envelope |
| `POST` | `/agent/policy-results` | Report per-control apply/verify results | Must reference the signed policy version |
| `POST` | `/agent/events:batch` | Upload bounded batch of structured events | Size and event-rate limits; no file content |
| `POST` | `/agent/updates/check` | Check approved signed agent release metadata | Never execute an unsigned update |

### Policy Rollback Semantics (F-007)
A policy rollback (`POST /admin/policies/{policy_id}/rollback`) publishes a **new** `policy_version` number (N+1) whose `rollback_of_version` metadata field references the prior safe version. The agent accepts this policy because the version number is strictly greater than its currently applied version (`policy_version > current_applied_version`), maintaining the agent's monotonic anti-downgrade protection invariant while restoring safe control settings.

## 5. Agent policy retrieval response

Return:

```json
{
  "policy_id": "00000000-0000-4000-8000-000000000001",
  "policy_version": 12,
  "schema_version": "1.0.0",
  "issued_at": "2026-10-22T12:00:00Z",
  "expires_at": "2026-10-23T12:00:00Z",
  "target_device_id": "00000000-0000-4000-8000-000000000002",
  "digest_sha256": "<hex digest of canonical policy bytes>",
  "signature": "<base64 signature over documented canonical envelope>",
  "policy": {}
}
```

> **Normative Signing Authority (F-001):** See [`SIGNING_SPEC.md`](SIGNING_SPEC.md) for the exact specification of the canonical envelope, JSON canonicalization (RFC 8785 / JCS), Ed25519 signature algorithm, and key identifier conventions. The API and agent must not negotiate arbitrary algorithms.

## 6. Control result model and device status vocabulary

Each control result reported by the agent includes:

- `control_id`, `status`, `observed_at`, `provider`, `provider_version` when available.
- `desired_state` and `observed_state` as bounded enums or typed objects.
- `evidence` with non-sensitive registry/policy identifiers where appropriate.
- `error_code` and a safe message if failed.
- `safe_details`: bounded diagnostic string (max 1000 chars) strictly conforming to the allowlist defined in [`ENDPOINT_AGENT.md`](ENDPOINT_AGENT.md) Section 5. The API enforces pattern rejection against secrets, auth tokens, file contents, file paths outside allowed system roots, and email addresses.

Allowed per-control status values: `enforced`, `partial`, `failed`, `unsupported`, `not_configured`, `unknown`.

The control plane derives device compliance from required controls and freshness rules; it must not trust an agent-supplied overall `compliant: true` without evaluating the per-control facts.

### Device Status Vocabulary (F-016)
The canonical device status enum in the database and API is:
`enrolled` | `compliant` | `noncompliant` | `stale` | `revoked` | `unknown`

Derived dashboard UI states:
- `partial`: Device has at least one control reporting `partial` or `unsupported` while all other mandatory controls are `enforced`.
- `unsupported`: Device OS or edition cannot satisfy one or more required policy controls.

## 7. Error shape

```json
{
  "error": {
    "code": "POLICY_VERSION_CONFLICT",
    "message": "The policy has changed. Reload it and retry.",
    "request_id": "00000000-0000-4000-8000-000000000003"
  }
}
```

Do not return secrets, stack traces, raw SQL errors or internal infrastructure details.

## 8. Security-critical behaviors

- **Enrollment code generation and verification (F-011):**
  - Minimum entropy: at least 128 bits of cryptographically secure random entropy (CSPRNG).
  - Character set: RFC 4648 Base32 (unambiguous, case-insensitive) or URL-safe Base64, minimum 26 characters.
  - At-rest storage: Stored as SHA-256 hash with a per-tenant salt. The plaintext code is displayed once to the administrator and never persisted in database logs or audit payloads.
  - Expiry: 300 seconds (5 minutes) default for pilot, maximum 600 seconds.
  - Single-use: Immediately invalidated upon successful enrollment or after 3 failed attempts. Rate limited to 5 attempts/minute per IP/tenant.
- Policy publish requires schema validation, author/approver separation for high-impact policies, signature creation and an audit record.
- Policy result endpoints are idempotent and reject results for unknown policy versions.
- Event upload validates every field and enforces payload/count/rate limits.
- Device revocation invalidates credentials and is propagated to repository/DLP integrations where supported.
- Pagination and filters are bounded to prevent resource exhaustion.
- Cross-device and cross-tenant object access tests are mandatory.
