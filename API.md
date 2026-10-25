# WorkGuard API Contract

**Version:** `v1` — implemented by `control-api/app`.

The machine-readable contract is generated from the FastAPI application into
[`openapi.yaml`](openapi.yaml). This document explains the security-relevant
behaviour that an OpenAPI schema cannot express.

## 1. Conventions

- Base path: `/api/v1`.
- JSON request/response, UTF-8.
- TLS is required outside local development.
- Administrator authentication:
  - `AUTH_MODE=oidc`: `Authorization: Bearer <OIDC access token>` with a
    configured issuer, audience and role claim.
  - `AUTH_MODE=dev`: `X-Dev-User` and `X-Dev-Role`, accepted **only** when
    `APP_ENV=local`, `AUTH_MODE=dev`, and `ALLOW_DEV_AUTH=1`. This is local
    tooling, not an authentication mechanism for a deployed service.
- Agent authentication: `Authorization: Bearer <per-device token>` obtained
  from enrollment. The device identity is derived from the token hash. The
  legacy `X-Device-Id` fallback is disabled by default and is local-only.
- All timestamps are RFC 3339 with an explicit UTC offset.
- List endpoints use opaque cursor pagination (`cursor`, `limit`), default 50,
  maximum 200.
- Every response carries `X-Request-ID`; errors repeat it in the body. A
  client-supplied `X-Request-ID` is accepted only if it matches
  `^[A-Za-z0-9._:-]{1,128}$`.
- Request bodies are capped by `MAX_EVENT_PAYLOAD_BYTES` when
  `Content-Length` is present. Edge/proxy limits are still required.
- Mutating admin requests accept `Idempotency-Key` at the HTTP layer, but the
  current implementation does not deduplicate arbitrary requests. Event upload
  is idempotent by event `id`.

## 2. Roles

| Role | Capabilities |
|---|---|
| `security_admin` | Create enrollment codes, revoke devices, rotate credentials, create/edit/submit/approve/publish/rollback policies, create/revoke exceptions. |
| `it_operator` | Read devices, policies, events, audit records and exceptions. Cannot mutate. |
| `auditor` | Read devices, policies, events, audit records and exceptions. Cannot mutate. |
| `agent` | Access only its own device identity, assignment, results and events. |

The author of a policy cannot approve or publish it. Approval and publication
require `security_admin`. There is no separate "release manager" role in this
build.

## 3. Administrator routes

| Method | Path | Purpose | Access |
|---|---|---|---|
| `GET` | `/health/live` | Process liveness | public |
| `GET` | `/health/ready` | Database readiness | public |
| `GET` | `/api/v1` | Service metadata and auth mode | public |
| `GET` | `/admin/devices` | List/search devices | auditor+ |
| `GET` | `/admin/devices/{device_id}` | Device detail, control results, compliance details | auditor+ |
| `POST` | `/admin/devices/{device_id}/revoke` | Revoke device and clear its credential | security_admin; reason required |
| `POST` | `/admin/devices/{device_id}/rotate-credential` | Issue a new device bearer token | security_admin |
| `POST` | `/admin/enrollment-codes` | Create a single-use enrollment code | security_admin |
| `GET` | `/admin/policies` | List policies | auditor+ |
| `POST` | `/admin/policies` | Create a draft policy | security_admin |
| `GET` | `/admin/policies/{policy_id}` | Policy content, state and versions | auditor+ |
| `GET` | `/admin/policies/{policy_id}/versions` | Version history | auditor+ |
| `PATCH` | `/admin/policies/{policy_id}` | Edit a draft only | security_admin |
| `POST` | `/admin/policies/{policy_id}/new-draft` | Clone the published version into the next draft | security_admin |
| `POST` | `/admin/policies/{policy_id}/submit` | Move draft → submitted | security_admin |
| `POST` | `/admin/policies/{policy_id}/approve` | Move submitted → approved; author excluded | security_admin, different user |
| `POST` | `/admin/policies/{policy_id}/publish` | Move approved → published and assign to the fleet | security_admin, author excluded |
| `POST` | `/admin/policies/{policy_id}/rollback` | Publish prior content as a new greater version | security_admin; reason required |
| `GET` | `/admin/events` | List security events | auditor+ |
| `GET` | `/admin/audit-events` | List admin audit records | auditor+ |
| `GET` | `/admin/audit-events/verify` | Recompute the audit hash chain | auditor+ |
| `GET` | `/admin/exceptions` | List exceptions (expired statuses refreshed) | auditor+ |
| `POST` | `/admin/exceptions` | Create a scoped, expiring exception | security_admin |
| `POST` | `/admin/exceptions/{exception_id}/revoke` | Revoke an exception | security_admin |

## 4. Agent routes

| Method | Path | Purpose | Notes |
|---|---|---|---|
| `GET` | `/agent/keys` | Publish Ed25519 verification keys (JWKS) | public, cacheable |
| `POST` | `/agent/enroll` | Exchange a one-time code for a device identity | rate limited; single use |
| `POST` | `/agent/heartbeat` | Liveness, versions, observed policy version | metadata only |
| `GET` | `/agent/policies/current` | Fetch a signed, device-targeted policy envelope | `204` if no assignment |
| `POST` | `/agent/policy-results` | Report per-control read-back results | idempotent per device/version/control |
| `POST` | `/agent/events:batch` | Upload bounded structured events | no file contents |
| `POST` | `/agent/credential/rotate` | Rotate the authenticated device's token | old token stops working |
| `POST` | `/agent/updates/check` | Check for a signed agent release | returns no update in this build |

## 5. Policy lifecycle

1. `POST /admin/policies` creates a draft at version 1. The server assigns the
   policy id and forces `policy_version` to 1.
2. Drafts can be edited with `PATCH`. Each edit revalidates the canonical JSON
   Schema. The draft keeps its version.
3. `POST .../submit` moves `draft → submitted`.
4. `POST .../approve` requires a `security_admin` whose identity differs from
   `created_by`; it records `approved_by` and the approval notes.
5. `POST .../publish` requires the approved state and an identity different
   from the author. It publishes the **existing draft version**; it does not
   invent an extra increment. The version row becomes immutable and is
   assigned to all non-revoked devices.
6. `POST .../new-draft` clones the currently published content into version
   `N+1` and moves the policy back to `draft`. The published version stays
   active for devices until the new draft is published.
7. `POST .../rollback` copies the selected historical content into version
   `latest + 1` with `rollback_of_version` metadata. It is accepted only when
   the policy is in the `published` state (no draft, submission or approval is
   pending) and the target is an earlier published version. This prevents the
   rollback path from publishing unapproved draft content. The rollback actor
   must also differ from the policy author, matching the publication rule.
   Rollback is audited but does not require a separate approval step in this
   build.

The stored version row contains the canonical policy content and its SHA-256
digest. It intentionally does **not** contain a reusable signature: the
signature covers a short-lived envelope bound to one device and is generated at
fetch time.

## 6. Agent policy retrieval response

`GET /agent/policies/current` returns the envelope defined by
[`SIGNING_SPEC.md`](SIGNING_SPEC.md):

```json
{
  "spec_version": "1",
  "policy_id": "00000000-0000-4000-8000-000000000001",
  "policy_version": 12,
  "schema_version": "1.0.0",
  "issued_at": "2026-10-25T12:00:00Z",
  "expires_at": "2026-10-25T13:00:00Z",
  "target_device_id": "00000000-0000-4000-8000-000000000002",
  "digest_sha256": "<hex SHA-256 of the RFC 8785 policy bytes>",
  "key_id": "wg-policy-local-v1",
  "policy": {},
  "signature": "<standard base64 Ed25519 signature over the canonical envelope without this field>"
}
```

The agent verifies, in order: object shape and unknown fields, `spec_version`,
target device, timestamp validity and ordering, monotonic policy version, known
`key_id`, schema version, policy presence, Ed25519 signature over RFC 8785
bytes, digest match, and inner `policy_id` / `policy_version` match. A failure
must preserve the last-known-good policy and emit a `policy.rejected` event.

## 7. Control results and compliance

Each result contains `control_id`, `status`, `provider`, `observed_at`, and
optional `provider_version`, `error_code`, and `safe_details`.

Allowed statuses: `enforced`, `partial`, `failed`, `unsupported`,
`not_configured`, `unknown`.

The control plane derives device status; it does not trust an agent-wide
compliant flag:

- `revoked` — device credential revoked.
- `enrolled` — no published policy assignment.
- `stale` — heartbeat older than `DEVICE_STALE_AFTER_SECONDS`.
- `noncompliant` — at least one required control is not `enforced` and is not
  covered by an active, unexpired exception.
- `compliant` — every required control is `enforced`, or is covered by an
  active exception (reported separately as `excepted`).

`GET /admin/devices/{id}` exposes `compliance_details`. Entries with
`status: "excepted"` include the exception id and expiry; they are not counted
as enforcement evidence.

Results are evaluated against the device's **currently desired** version. A
result submitted for an older applied version is recorded but cannot make the
device compliant with a newer policy. Publishing a new version immediately
re-derives every assigned device's status, so a device does not remain
`compliant` on the strength of read-backs for the previous version.

A pending draft does not remove the last published version from devices: the
policy row may be `draft`, `submitted` or `approved`, but agents continue to
receive the version recorded in `current_version` until a new version is
published.

## 8. Error shape

```json
{
  "error": {
    "code": "HTTP_409",
    "message": "Policy must be approved before publishing",
    "request_id": "00000000-0000-4000-8000-000000000003"
  }
}
```

Validation failures use `422` with `VALIDATION_ERROR` and a bounded message.
Unhandled errors return `500` with `INTERNAL_ERROR`; stack traces and secrets
are never returned.

## 9. Security-critical behaviours

- **Enrollment codes:** at least 128 bits of CSPRNG entropy, RFC 4648 Base32,
  single use, default 300 s lifetime (request maximum 600 s). Stored as
  HMAC-SHA-256 with `ENROLLMENT_CODE_PEPPER`; plaintext is returned once and
  never written to the audit log. Invalid/expired/reused codes are rejected.
  The enrollment endpoint is rate limited per client address (10/min); there is
  no per-code "three failures" counter because an invalid code has no row to
  attribute attempts to.
- **Device tokens:** 256-bit random URL-safe tokens prefixed `wg1_`, stored as
  HMAC-SHA-256 with `DEVICE_TOKEN_PEPPER`. Rotation invalidates the old token
  immediately. Revocation clears the stored hash.
- **Policy validation:** every create, edit, submit, approve, publish and
  rollback path validates against `schemas/policy.schema.json`, including
  per-control settings and unique control ids.
- **Publish:** requires the approved state, a different identity from the
  author, and a version equal to the latest draft version.
- **Events:** every event field is validated; batches are capped by
  `MAX_EVENT_BATCH_SIZE`; event ids are idempotent; a device cannot submit an
  event for another device.
- **Safe details:** length-bounded and pattern-rejected for private keys,
  bearer tokens, passwords, API keys, cloud keys and email addresses.
- **Audit:** each admin record is SHA-256 chained to the previous record.
  Verification recomputes the chain and reports the first broken record.
  This is tamper-evident, not externally immutable.
- **Freshness:** a background sweep marks devices stale; a fresh heartbeat
  recomputes status. A stale device cannot be reported as compliant.

## 10. Not part of this API yet

- Device mTLS or certificate-bound credentials.
- Multi-tenant object scoping beyond the `org_id` column.
- Signed agent update artifacts and a release feed.
- Per-request idempotency-key storage for admin mutations.
- External immutable audit/SIEM export.
- A real DLP/browser/network integration.
