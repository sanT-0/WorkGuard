# WorkGuard

**Status: working local MVP, not a production endpoint-security product.**

WorkGuard is a control plane for managing security policy on company-managed
Windows laptops. This repository currently implements the control plane, a
development console, and an endpoint **simulator**. It does not yet contain a
real Windows service and does not enforce Windows policy by itself.

The design rule is simple: WorkGuard may orchestrate supported platform
controls, but it must never claim enforcement that has not been read back from
the endpoint.

## What is implemented

- **FastAPI control plane** (`control-api/`) with SQLite persistence and a
  migration-in-place schema.
- **Signed policy delivery** using Ed25519 over an RFC 8785 (JCS) canonical
  envelope, with a published JWKS (`GET /api/v1/agent/keys`).
- **Immutable policy versions**: drafts are editable; publish promotes the
  draft version; rollback publishes restored content as a new, greater version
  (`N+1`) so anti-downgrade remains valid.
- **Two-person lifecycle**: submit → approve (author cannot approve) → publish
  (author cannot publish). The approval and publication identities are audited.
- **Device identity**: one-time enrollment codes exchanged for per-device
  bearer tokens. Tokens are stored as HMAC-SHA-256 hashes; the server derives
  device identity from the token, not from a client-supplied device header.
- **Enrollment, heartbeat, policy fetch, result upload, event batch, credential
  rotation, device revocation.**
- **Compliance derivation** from required per-control results plus heartbeat
  freshness. Unsupported/failed/missing controls are non-compliant; approved,
  unexpired exceptions are shown separately as `excepted`.
- **Tamper-evident admin audit chain** with a verification endpoint.
- **Scoped, expiring exceptions** with duplicate-active prevention and audit.
- **Administrator console** (`admin-web/`) that drives the real API: identity
  selection for local dev or OIDC bearer tokens, device inspection, policy
  editing, approval, publication, rollback, enrollment, events, audit
  verification, and exceptions.
- **Test suite** covering signing/verification, lifecycle invariants, RBAC,
  device auth, revocation, rotation, enrollment, exceptions, freshness, audit
  tampering, and console safety invariants.

## What is not implemented

- A real Windows `.NET` service, MSI installer, service hardening, provider
  adapters, or actual USB/BitLocker/AppLocker/firewall enforcement.
- Endpoint DLP or browser/network upload interception. The simulator reports
  `not_configured` for DLP and never claims coverage.
- mTLS/device certificates (the implemented agent credential is a bearer
  token).
- PostgreSQL, multi-tenant isolation beyond `org_id` fields, KMS/HSM signing
  integration, SIEM export, and a signed agent update feed.
- Real OIDC integration testing. The OIDC verification path exists but has not
  been exercised against a live identity provider.
- A production-grade frontend build pipeline. The console is a static
  HTML/CSS/JS application served by the API.

Do not deploy this as a security control for real source code until the Phase 3
gates in [`ROADMAP.md`](ROADMAP.md) and the Windows agent work are complete.

## Quick start (Windows PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r control-api\requirements-dev.txt

$env:APP_ENV = "local"
$env:AUTH_MODE = "dev"
$env:ALLOW_DEV_AUTH = "1"

cd control-api
..\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

Open <http://127.0.0.1:8000/>. The console defaults to acting as `dev-admin`
with the `security_admin` role. To exercise the two-person flow, create a draft,
submit it, change **Acting as** to another user (for example `approver-2`),
approve it, then publish as a third identity.

Development authentication trusts `X-Dev-User` / `X-Dev-Role` **only** when
`APP_ENV=local`, `AUTH_MODE=dev`, and `ALLOW_DEV_AUTH=1`. Never expose this
process beyond localhost in that mode.

The first run creates a local signing key at
`control-api/.local/policy_signing_key.pem` and simulator tokens at
`control-api/.dev-device-tokens.json`. Both are git-ignored. Non-local startup
fails if the signing key is missing or the credential peppers are still the
development defaults, and it never seeds demo devices or writes the simulator
token file: a deployed control plane starts empty and issues credentials only
through enrollment.

### Endpoint simulator

From the repository root, with the API running:

```powershell
.\.venv\Scripts\python.exe endpoint-agent\simulator.py sync
.\.venv\Scripts\python.exe endpoint-agent\simulator.py usb
.\.venv\Scripts\python.exe endpoint-agent\simulator.py enroll WG-...
```

The simulator fetches the policy, verifies the envelope and schema, rejects
downgrades, and reports **simulated** read-back results. It is a contract test
harness, not an enforcement agent.

## Tests

```powershell
cd control-api
..\.venv\Scripts\python.exe -m pytest
..\.venv\Scripts\python.exe -m ruff check app tests
```

Tests use temporary databases, token files, and signing keys. They do not touch
your local development data.

## Security model in one page

- Policy content is stored with a SHA-256 digest. At fetch time the server builds
  a short-lived, device-targeted envelope and signs the canonical bytes with
  Ed25519. Agents verify spec version, target device, timestamps, key id,
  signature, digest, and inner policy identity before applying anything.
- Policy versions are monotonic. The agent rejects versions below its last
  applied version.
- Agent requests authenticate with a per-device bearer token. The device id is
  never taken from a request header unless the insecure local fallback is
  explicitly enabled.
- Admin mutations require a role; publish and approve require a
  `security_admin`, and the author cannot approve or publish their own policy.
- Admin audit rows are hash-chained. Verification detects modification of rows
  written by this build; it is not an external immutable sink.
- Enrollment codes are high-entropy, single-use, expiring, and rate limited.
  They are stored as keyed HMAC hashes, not plaintext.

Known limitations are documented in [`SECURITY.md`](SECURITY.md),
[`THREAT_MODEL.md`](THREAT_MODEL.md), and [`CHANNEL_COVERAGE.md`](CHANNEL_COVERAGE.md).

## Repository layout

```text
admin-web/          Static administrator console (index.html + app.js)
control-api/        FastAPI application, SQLite schema, tests
endpoint-agent/     Development simulator (not the Windows service)
schemas/            Canonical policy JSON Schema
diagrams/           Architecture diagrams
*.md                Architecture, API, signing, security, testing and roadmap docs
```

## Documentation map

- [`ARCHITECTURE.md`](ARCHITECTURE.md) — system architecture and trust boundaries
- [`SECURITY.md`](SECURITY.md) — security requirements and hardening rules
- [`SIGNING_SPEC.md`](SIGNING_SPEC.md) — normative Ed25519 + RFC 8785 envelope
- [`API.md`](API.md) — implemented API contract and behaviours
- [`openapi.yaml`](openapi.yaml) — machine-readable OpenAPI generated from the app
- [`ENDPOINT_AGENT.md`](ENDPOINT_AGENT.md) — proposed Windows service design
- [`CHANNEL_COVERAGE.md`](CHANNEL_COVERAGE.md) — DLP channel matrix and status
- [`DESIGN.md`](DESIGN.md) — product UX and policy states
- [`DATA_MODEL.md`](DATA_MODEL.md) — entities and retention
- [`OPERATIONS.md`](OPERATIONS.md) — operational runbooks
- [`TESTING.md`](TESTING.md) — test plan and acceptance matrix
- [`ROADMAP.md`](ROADMAP.md) — staged plan and phase gates
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — contribution rules
- [`schemas/policy.schema.json`](schemas/policy.schema.json) — policy schema
