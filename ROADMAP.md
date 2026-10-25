# WorkGuard Implementation Roadmap

## Current implementation status

- **Phase 0:** documentation exists; company-specific discovery and sign-off are
  still required.
- **Phase 1:** mostly implemented, with deviations: SQLite instead of
  PostgreSQL, a static HTML/JS console instead of React, and an OIDC code path
  that has not been tested against a live identity provider. Enrollment,
  revocation, policy lifecycle, audit, and the simulator are implemented.
- **Phase 2:** not started. There is no signed .NET service, installer, mTLS, or
  real Windows provider adapter. `endpoint-agent/simulator.py` is a contract
  harness only.
- **Phase 3–5:** not started.
- Scoped, expiring exceptions (a Phase 4 item) are implemented in the control
  plane and console, but no endpoint adapter consumes them for enforcement.

## Phase 0 — Discovery and acceptance criteria

Deliverables:
- Inventory Windows versions/editions, device ownership, existing Microsoft/security licensing, repo host and file types.
- Employee telemetry notice and data retention proposal.
- Transfer-channel coverage matrix.
- Pilot success/rollback criteria.

Exit gate: company agrees what "code leak prevention" means and acknowledges residual risks.

## Phase 1 — Control-plane skeleton

Build:
- React admin authentication via OIDC.
- FastAPI API, PostgreSQL migrations, organization/role model.
- Device enrollment and revocation flow.
- Policy templates and audit events.
- Fake-agent simulator for API tests.

Do not enforce endpoint controls yet.

## Phase 2 — Windows agent proof of concept

Build:
- Signed C#/.NET service and installer for test devices.
- Device identity with protected credential storage.
- Heartbeat and signed policy retrieval.
- Schema/signature/version validation.
- One read-only control: report OS/version/encryption state where available.
- One limited enforcement adapter for removable storage using a supported Windows control.
- Apply/read-back evidence and error reporting.

Exit gate: signature tampering and policy downgrade rejected; device shows `enforced` only after read-back verification.

## Phase 3 — Application control and endpoint hardening

- Build policy in audit mode on pilot machines.
- Review blocked/allowed developer applications.
- Add staged rollout and rollback.
- Integrate endpoint protection status and application-control provider.

Exit gate: supported developer workflow passes and recovery is tested.

## Phase 4 — Data-transfer protection

- Select a supported endpoint DLP/secure web gateway based on required channel coverage, budget and platform requirements.
- Integrate policy configuration/status through supported vendor interfaces where available.
- Build tests for browser upload, sync client, email, Git, messaging, print and network share.
- Implement scoped, expiring exceptions.

Exit gate: document per-channel coverage; do not market unsupported channels as blocked.

## Phase 5 — Pilot, operate and expand

- Start with 1–2 test laptops using synthetic data, then a small employee cohort.
- Monitor false positives, developer productivity and support requests.
- Run incident and offboarding drills.
- Add additional employee devices only after sign-off.

## Suggested MVP cut line

For the first useful MVP, target only: device enrollment, admin login, device inventory, signed policy retrieval, USB policy adapter, agent heartbeat, control verification, audit log and policy rollback. Upload DLP is a separate integration and should not be simulated by a dashboard toggle.
