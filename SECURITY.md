# WorkGuard Security Requirements

> **Implementation status:** this is the requirements document, not a statement
> that every control is deployed. The current local MVP implements schema
> validation, Ed25519 envelope signing/verification, RBAC, per-device bearer
> tokens, HMAC-hashed credentials, immutable policy versions, author/approver
> separation, audit chaining, rate limits, and freshness. It does **not** yet
> implement mTLS, MFA/step-up authentication, HSM-backed keys, PostgreSQL
> least-privilege roles, tenant-scoped object authorization beyond `org_id`,
> an external immutable audit sink, or real endpoint enforcement/DLP. See
> `README.md` and `ROADMAP.md` for the exact boundary.

## 1. Security objectives

- Reduce unauthorized copying of company source code and work files.
- Enforce approved removable-storage and application policies on managed endpoints.
- Restrict transfers to unauthorized destinations where supported by verified DLP/web/network controls.
- Prevent unauthorized administrators from changing policies or accessing tenant/device data.
- Detect policy drift, stale devices, agent tampering, credential abuse and suspicious administrative actions.
- Protect the integrity, confidentiality and availability of control-plane metadata and policy.

## 2. Security requirements

### Identity and access

- Use a mature OIDC identity provider for interactive administrators; require MFA and strong session controls.
- Use per-device credentials for agents. Support credential rotation and immediate revocation.
- Never place API keys, private signing keys, or shared device secrets in source code, client bundles, or a common installer secret.
- Enforce RBAC in the API for every action and object. UI hiding is not authorization.
- Require step-up authentication or dual approval for high-impact actions: policy enforcement, exclusions, device unenrollment, credential revocation and changes to telemetry.
- Offboarding runbook revokes identity, sessions, device credentials and repository access.

### API and data

- TLS for all network communication; use mTLS or equivalent device-bound proof for agent endpoints.
- Validate every request against explicit schemas, size limits and allowlisted enum values.
- Use parameterized database queries and least-privilege DB roles.
- Protect against broken object-level authorization by checking tenant, device and project scope on every query and mutation.
- Use short-lived tokens, audience/issuer/expiry validation, key rotation and revocation paths.
- Apply rate limits to enrollment, authentication, event ingestion, and policy retrieval.
- Redact tokens, enrollment codes, secrets, personal file paths and sensitive request bodies from logs.
- Use append-oriented audit records; restrict delete/update privileges and export logs to a protected sink where feasible.
- Encrypt managed database backups and test restoration.

### Policy integrity

- A policy has a schema version, policy ID, monotonically increasing version, target scope, issued time, expiry time, author, reason, approval metadata and signature.
- Agent verifies the signature over a canonical byte representation, not a re-serialized ambiguous object.
- Reject unknown critical fields, invalid signatures, expired policies, version downgrade and device-scope mismatch.
- Keep signing keys in a dedicated secret manager/HSM-backed service where possible; do not reuse TLS keys for policy signing.
- Separate policy authoring from release/signing authority.
- Maintain last-known-good policy and a tested rollback process.

### Endpoint agent

- Distribute only signed releases from a controlled pipeline.
- Use minimal privileges; isolate network parsing from privileged policy-application code where practical.
- Authenticate local IPC; ACL named pipes/files to trusted principals; avoid unauthenticated localhost listeners.
- Enforce secure update verification, anti-rollback and recovery from interrupted updates.
- Do not add keylogging, covert screenshots, clipboard collection, credential extraction, process injection, stealth/persistence beyond documented service operation, or bypasses of platform security.
- Do not write a kernel driver for the initial product. If a future requirement genuinely needs one, perform specialist threat modeling, code review, driver security testing and the platform's current signing process. See Microsoft's [driver security checklist](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist).

### DLP and transfer controls

- Model channel coverage explicitly (USB, browser upload, sync client, mail, Git, print, Bluetooth, network share, clipboard, screenshot, remote access). Do not assume one control covers all channels.
- Use supported, documented endpoint DLP/browser/network controls. Test exact supported browsers, apps, Windows editions and licensing.
- Apply default deny to unapproved transfers only after confirming legitimate workflows and exceptions.
- Allow exceptions to be device/user scoped, justified, approved and time-limited.
- Do not promise prevention for camera photography, manual transcription or any channel not technically controlled.

### Privacy and employee transparency

- Provide employee notice before enrollment: purpose, exact event categories, retention, who can access data, incident use, and contact for questions.
- Collect the minimum telemetry necessary to enforce and troubleshoot policy.
- No content capture by default: no source-code upload, keystrokes, screenshots, clipboard contents, audio/video, or unrelated browsing history.
- Restrict administrator access to security data and audit the access itself.
- Define retention periods and deletion processes with legal/HR review appropriate to the operating jurisdiction.

## 3. Recommended default posture

- Company-owned and company-managed Windows endpoints only.
- Disk encryption required.
- Standard user for daily work; separate managed admin account.
- USB mass storage denied by default; documented exception process if required.
- Application control initially audited, then enforced after compatibility validation.
- DLP for approved channel coverage; personal cloud/email and public repositories blocked where supported.
- Endpoint protection active and up to date.
- Agent heartbeat and policy verification required; stale devices become noncompliant.
- Repository access uses MFA, least privilege, protected branches and credential/secret scanning.
- No production secrets on developer laptops unless approved and protected; use short-lived credentials.

## 4. Security event taxonomy

Minimum event types:

- `device.enrolled`, `device.revoked`, `device.stale`, `device.compliance_changed`
- `policy.created`, `policy.approved`, `policy.published`, `policy.rejected`, `policy.rollback`
- `control.enforced`, `control.failed`, `control.unsupported`, `control.drift_detected`
- `agent.integrity_failed`, `agent.update_failed`, `agent.version_outdated`
- `transfer.blocked`, `transfer.allowed_by_exception` (only when supported by integrated control)
- `admin.login_failed`, `admin.role_changed`, `admin.exception_created`, `admin.audit_exported`

Events should state what was verified; use provider/source metadata and do not invent a blocked action from an attempted or inferred action.

## 5. Incident severity and response

- **Critical:** probable credential compromise, policy-signing key exposure, widespread endpoint control bypass. Revoke/rotate credentials, suspend policy publishing, preserve logs, engage incident owner.
- **High:** device reports control tampering, untrusted policy signature, or confirmed unauthorized transfer event. Quarantine or revoke sensitive access according to policy; investigate device and account.
- **Medium:** agent stale, repeated enforcement failures, unsupported control or unusual admin activity. Open remediation case and restrict sensitive access if unresolved.
- **Low:** expected policy drift during maintenance or known blocked attempt with no evidence of exfiltration. Record and review trends.

Do not automatically delete employee data or wipe devices without a separately authorized, tested response procedure.

## 6. Release security gates

A release cannot ship until:
- Threat model reviewed and changes documented.
- Static analysis, dependency scanning, secret scanning and unit tests pass.
- API authorization and tenancy tests pass.
- Signed-policy tampering, replay and downgrade tests pass.
- Agent updater signature/rollback tests pass.
- Windows policies tested on each supported OS edition and build matrix.
- No unresolved critical/high vulnerabilities without written risk acceptance.
- Incident response, rollback and backup restoration verified.

## 7. Responsible disclosure

Report vulnerabilities privately to the designated security contact in the company's approved process. Do not include production credentials, source code or employee personal data in a report. Define a contact and response SLA before external or employee pilot deployment.
