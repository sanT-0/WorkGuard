# WorkGuard Architecture & Documentation Audit Report

> **Audit date:** 2026-10-22
> **Auditor role:** Principal Software Architect / Windows Endpoint Security Engineer / Application Security Auditor
> **Files read:** README.md, ARCHITECTURE.md, SECURITY.md, DESIGN.md, API.md, ENDPOINT_AGENT.md, THREAT_MODEL.md, DATA_MODEL.md, DEPLOYMENT.md, OPERATIONS.md, TESTING.md, ROADMAP.md, CONTRIBUTING.md, openapi.yaml, schemas/policy.schema.json, .env.example, .gitignore, diagrams/README.md
> **Missing files:** None of the listed target files are absent. No implementation code exists (expected for this documentation phase).

---

## A. Executive Verdict

| Gate | Verdict | Rationale |
|---|---|---|
| **Architecture approval** | APPROVED WITH CONDITIONS | The architecture is internally consistent, honest about its scope, and avoids most common DLP-theatre traps. Conditions: resolve the 14 open design decisions listed in Section 8 of ARCHITECTURE.md before implementation begins. |
| **Beginning implementation** | CONDITIONALLY READY | P1 gaps must be closed first (see Section C). Implementation can begin on Phase 0-1 (control-plane skeleton, enrollment, OIDC, DB) immediately. Agent enforcement and DLP integration must not begin until USB mechanism, Windows-edition matrix, and DLP vendor are selected and documented. |
| **Controlled security pilot** | NOT READY | DLP channel coverage matrix is incomplete, signing algorithm is unspecified, agent hardening detail is insufficient, cost/licensing matrix is absent, and no concrete acceptance criteria with pass/fail evidence is written for the pilot gating. |
| **Production deployment** | NOT READY | Requires everything above plus: external security review of the agent, HSM-backed signing, full transfer-channel test matrix, offboarding drills, backup-restoration proof, compliance/privacy review, and a designated incident owner. |

---

## B. Requirement Coverage Matrix

| # | Requirement | Relevant Documents | Status | Evidence | Risk / Limitation | Required Correction |
|---|---|---|---|---|---|---|
| R1 | Keep source code on employee laptops | ARCHITECTURE s1,s4; README s1 | PASS | "Source code and active project files remain on each employee laptop by default" (ARCHITECTURE.md:5) | Physical and screen-capture risk remains | Confirm in employee telemetry notice |
| R2 | No physical company server | DEPLOYMENT s1,s2 | PASS | "prefer managed cloud services" (DEPLOYMENT.md:5) | Cloud provider SLA and data-residency must be selected | Choose specific cloud provider before pilot |
| R3 | React + TypeScript dashboard | ARCHITECTURE s3.1 | PASS | "React + TypeScript" (ARCHITECTURE.md:24) | No build toolchain specified | Add toolchain choice (e.g., Vite) to ROADMAP Phase 1 |
| R4 | Python + FastAPI backend | ARCHITECTURE s3.2 | PASS | Stated at ARCHITECTURE.md:31 | Python version and dependency manager not specified | Add to DEPLOYMENT.md |
| R5 | PostgreSQL for metadata | ARCHITECTURE s3.2; DATA_MODEL | PASS | Consistently stated across files | ORM/migration tool not specified | Add Alembic or equivalent to ROADMAP |
| R6 | C#/.NET Windows agent | ARCHITECTURE s3.4; ENDPOINT_AGENT s2 | PASS | "C#/.NET Windows service" (ENDPOINT_AGENT.md:9) | .NET version not pinned | Pin to a named .NET LTS release |
| R7 | Signed MSI/EXE installer | ENDPOINT_AGENT s2; SECURITY sEndpoint | PASS | "Installer: signed MSI or equivalent" (ENDPOINT_AGENT.md:11) | Code-signing certificate cost and EV/OV distinction not discussed | Add signing cert requirement to DEPLOYMENT.md |
| R8 | Block USB storage | ENDPOINT_AGENT s5; ARCHITECTURE s3.5 | PARTIAL | Mechanism correctly deferred; no concrete decision made | Windows edition requirement for MDE device control unstated | Document exact mechanism and required edition before Phase 2 |
| R9 | Block unauthorized app execution | ENDPOINT_AGENT s5; ARCHITECTURE s3.5 | PARTIAL | App Control for Business and AppLocker named; choice deferred | AppLocker requires Enterprise/Education; choice determines fleet licensing | Document edition matrix and chosen mechanism before Phase 3 |
| R10 | Block browser uploads / file transfers | ENDPOINT_AGENT s5 (DLP adapter); SECURITY sDLP | PARTIAL | Correctly noted as requiring external DLP provider | No DLP vendor named; channel coverage matrix empty | Phase 4 requires selecting vendor and documenting coverage |
| R11 | Block personal cloud, email, Git | THREAT_MODEL s4; SECURITY sDLP | PARTIAL | Listed as threats; mitigation points to DLP integration | No vendor or channel matrix exists | Define which channels are in scope for MVP pilot |
| R12 | Admin-controlled policies | API.md; ARCHITECTURE s5; DESIGN sPolicy editor | PASS | Full policy lifecycle documented with approval, versioning, rollback | No role-based assignment of approval authority fully specified | Add approved_by enforcement logic to SECURITY gates |
| R13 | Security monitoring and audit logs | SECURITY sEvents; DATA_MODEL saudit; API.md s3 | PASS | Comprehensive event taxonomy and data model | Audit sink and log immutability are optional; no SIEM integration | Make audit-sink configuration required before pilot |
| R14 | Tamper resistance | ENDPOINT_AGENT s6; SECURITY sEndpoint | PARTIAL | Service ACL and standard-user restriction stated; no DACL values given | No PPL, no ELAM driver; local admin can still disable service | Specify exact service DACL; document residual local-admin bypass |
| R15 | Device compliance checks | DESIGN sDevice detail; API sControlResult | PASS | Per-control model with enforced/partial/failed/unsupported states; agent-supplied compliant rejected | Server-side derivation from agent facts | None required |
| R16 | Policy updates and rollback | ARCHITECTURE s5; API.md sRollback; OPERATIONS s4 | PASS | Monotonic versioning, rollback endpoint, rollback-of-version in DB | Rollback semantics are ambiguous (see F-007) | Clarify rollback versioning in API.md and ARCHITECTURE.md |
| R17 | Preserve developer workflows | ROADMAP sPhase 3; ENDPOINT_AGENT s5 | PASS | Audit-mode testing before enforcement; exception workflow documented | Approved package sources and authorized repo list not yet defined | Define approved-remotes and package-registry allowlist in Phase 3 |
| R18 | 6-20 employee scale | ARCHITECTURE s7; DEPLOYMENT s2 | PASS | Single API + single worker design; explicitly sized for small fleet | No explicit concurrency numbers given | Add expected TPS and sizing to DEPLOYMENT.md |
| R19 | Minimize cost | ROADMAP; DEPLOYMENT s2 | PARTIAL | Managed cloud services preferred; no cost estimates | MDE, Intune, EV cert, HSM, DLP all carry real costs | Add cost/licensing section to DEPLOYMENT.md |
| R20 | Technically honest guarantees | README sNon-goals; ARCHITECTURE s2; SECURITY sDLP | PASS | "cannot guarantee zero leakage" stated; camera/manual transcription called out as residual risk | None | Verify no document claims universal prevention |

---

## C. Findings by Severity

### P0 - Critical

#### F-001 - Policy signing algorithm is unspecified
- **Severity:** P0 - Critical
- **File:** API.md:81; openapi.yaml:452; schemas/policy.schema.json:5
- **Evidence:** API.md:81 states "Choose and document one canonical serialization format and signature algorithm before implementing it." The schema comment (policy.schema.json:5) repeats "Production must pin schema versions and implement canonical signing outside this raw JSON document." The signature field in the OpenAPI SignedPolicyEnvelope schema (openapi.yaml:452) has only minLength: 16 with no algorithm constraint.
- **Problem:** Without a pinned, documented signing algorithm (e.g., Ed25519 or RS256 over a canonical JSON encoding), two independently written components (the API signer and the agent verifier) cannot interoperate. An implementation team could choose a weak algorithm, use non-canonical serialization that allows signature bypass via ambiguous field ordering, or leave the agent unable to reject a forged policy. This is the most dangerous implementation gap.
- **Correction:** Add a new document (e.g., SIGNING_SPEC.md) specifying: (a) the exact signature algorithm (e.g., Ed25519), (b) the exact canonical encoding (e.g., RFC 8785 JSON Canonicalization Scheme), (c) the envelope fields covered by the signature, (d) the key identifier format, and (e) an algorithm version field so future rotation is safe.
- **Verification test:** Sign a policy with the correct key; tamper with one byte of the canonical envelope; verify the agent rejects it. Test algorithm downgrade by submitting a forged algorithm field; verify the agent rejects it.

#### F-002 - Device credential issuance flow is underspecified after enrollment
- **Severity:** P0 - Critical
- **File:** openapi.yaml:252-255; ENDPOINT_AGENT.md:11; API.md:12
- **Evidence:** The /agent/enroll response returns credential_enrollment_uri (openapi.yaml:254), but no document describes what that URI does, what PKI issues the certificate, how the private key is protected on the device, how renewal works, or how the server validates the certificate on subsequent calls. deviceAuth in the OpenAPI security scheme (openapi.yaml:353-354) is described as "Placeholder... implementation-specific."
- **Problem:** The device identity system - the root of trust for every subsequent agent API call - is entirely unimplemented in design. Without a PKI decision (self-signed CA vs. vendor-managed vs. ACME vs. Intune SCEP), the enrollment flow cannot be built, the mTLS claim in ARCHITECTURE.md:87 cannot be verified, and device impersonation is trivially possible during the gap.
- **Correction:** Write a PKI design section in ENDPOINT_AGENT.md specifying: (a) certificate authority choice, (b) how the private key is stored on the device (e.g., Windows CNG/TPM-backed), (c) certificate lifetime and renewal, (d) how the API validates the client certificate and ties it to a device record, (e) revocation method (CRL or OCSP). Until this is written, Phase 2 cannot safely begin.
- **Verification test:** Enroll a device, revoke it, attempt to reconnect; verify 401 returned. Attempt to use one device credential to fetch another device's policy; verify 403.

---

### P1 - High

#### F-003 - Windows edition and licensing matrix is entirely absent
- **Severity:** P1 - High
- **File:** ARCHITECTURE.md:133; ENDPOINT_AGENT.md:46-47; ROADMAP.md:6
- **Evidence:** ARCHITECTURE.md:133 lists "Windows 10/11 and editions in scope" as an open decision. ENDPOINT_AGENT.md:47 says "Document the exact supported Windows versions/editions" as a future task. No document contains an actual edition table.
- **Problem:** USB device control, App Control for Business, and endpoint DLP have different edition and licensing requirements. App Control for Business is unavailable on Windows 10/11 Home. Microsoft Defender for Endpoint Device Control requires MDE Plan 1 or Plan 2. AppLocker is available only on Enterprise and Education. If the company uses Windows Pro, several documented controls may be unavailable, making compliance reporting meaningless.
- **Correction:** Add a "Platform Support Matrix" table to ENDPOINT_AGENT.md listing each control, minimum Windows edition, required Microsoft license, and whether a fallback exists. Mark any controls requiring paid products as needing cost approval.
- **Verification test:** Build the matrix; verify controls are available on a real device running the declared edition before Phase 2 exit gate.

#### F-004 - DLP integration deferred without a vendor selection timeline or channel-coverage placeholder
- **Severity:** P1 - High
- **File:** ROADMAP.md:48-53; TESTING.md:3; THREAT_MODEL.md:6
- **Evidence:** ROADMAP.md Phase 4 says "Select a supported endpoint DLP/secure web gateway based on required channel coverage, budget and platform requirements." THREAT_MODEL.md:60 says channels "not tested must be documented as unknown, not secure." TESTING.md:50 says "A browser error by itself is not proof of enforced DLP." The channel-coverage matrix referenced by these files does not exist.
- **Problem:** A pilot cannot begin without knowing which channels are covered and which are not. Browser-upload blocking, personal cloud sync, personal email, and personal Git push are listed as requirements but have no concrete implementation path in the current MVP.
- **Correction:** Create a CHANNEL_COVERAGE.md document before Phase 3, listing every channel from TESTING.md Section 3, the proposed control mechanism for each, DLP vendor candidates, and explicit "unknown until tested" status for unresolved channels.
- **Verification test:** Document exists and reviewed before pilot. Every channel is categorized as: blocked (with evidence), allowed by exception, or unknown/out-of-scope.

#### F-005 - Service hardening requirements do not specify Windows service DACL values or PPL
- **Severity:** P1 - High
- **File:** ENDPOINT_AGENT.md:71; SECURITY.md:47-48
- **Evidence:** ENDPOINT_AGENT.md:71 says "Restrict service control permissions; standard users must not be able to stop/reconfigure the service." No specific DACL or SCM permission values are given; Protected Process Light (PPL) or ELAM are not mentioned.
- **Problem:** Without specifying the exact service DACL, a developer might implement incorrect permissions. A standard user or malware could stop the service silently. PPL is available for Windows services on Windows 8.1+ and prevents most user-mode process injection; it should be evaluated.
- **Correction:** Add a specific Windows service DACL string to ENDPOINT_AGENT.md Section 6. Document whether PPL is in scope and, if not, why and what compensating control applies. State the limitation that a stopped service cannot send its own tamper event.
- **Verification test:** As a standard Windows user, attempt sc stop WorkGuardAgent; verify access denied. Verify stopping the service generates a detectable event for the background worker.

#### F-006 - No concrete cost/licensing estimate for pilot or production
- **Severity:** P1 - High
- **File:** DEPLOYMENT.md; ROADMAP.md
- **Evidence:** DEPLOYMENT.md Section 2 lists "Managed PostgreSQL", "Secret manager/KMS", etc. as required services without naming providers or costs. ROADMAP.md Phase 4 says "Select a supported endpoint DLP/secure web gateway" without cost guidance.
- **Problem:** For a 6-20 person company, cost is a critical feasibility factor. MDE Plan 2 (~/device/month), Intune (~/device/month), EV code-signing cert (~-700/year), HSM key service (~-3/key/month), managed Postgres (~-200/month), and a commercial DLP product could easily exceed the budget of a small company before any application code is written.
- **Correction:** Add a "Cost and Licensing Estimates" section to DEPLOYMENT.md listing each cloud service, each Microsoft product with its SKU, code-signing certificate options, and DLP product licensing models. Date the estimates.
- **Verification test:** Management reviews and approves the cost estimate before Phase 1 begins.

#### F-007 - Rollback semantics are ambiguous between API.md and the data model
- **Severity:** P1 - High
- **File:** API.md:46; DATA_MODEL.md:35
- **Evidence:** API.md:46 defines POST /admin/policies/{policy_id}/rollback as "Publish prior approved policy version." DATA_MODEL.md:35 has rollback_of_version in policy_versions but no description of whether a rollback creates a new version number or reuses the old one. The agent performs monotonic version checks (ARCHITECTURE.md:114; SECURITY.md:39) - if rollback reuses the old version number, the agent will reject it as a downgrade.
- **Problem:** If rollback re-publishes a previous version without incrementing the version counter, it will be rejected by the agent's anti-downgrade check. This is a logical contradiction that will cause a production incident during a real emergency rollback.
- **Correction:** Add a paragraph to API.md Section 4 and ARCHITECTURE.md Section 5 explicitly stating: "A rollback publishes a new policy_version number (N+1) whose rollback_of_version references the prior safe version. The agent accepts it because the version number is strictly greater."
- **Verification test:** Publish version 5, rollback to version 3 content; verify the agent receives a policy with version 6 and applies it, and the dashboard shows the rollback reason.

#### F-008 - openapi.yaml is missing 10 of the ~20 API.md-defined endpoints
- **Severity:** P1 - High
- **File:** API.md:38-61; openapi.yaml (entire file)
- **Evidence:** The following endpoints defined in API.md are absent from openapi.yaml:
  - GET /admin/policies/{policy_id} (API.md:41)
  - PATCH /admin/policies/{policy_id} (API.md:42)
  - POST /admin/policies/{policy_id}/submit (API.md:43)
  - POST /admin/policies/{policy_id}/approve (API.md:44) - CRITICAL: second-person approval has no schema
  - POST /admin/policies/{policy_id}/rollback (API.md:46)
  - GET /admin/audit-events (API.md:48)
  - POST /admin/exceptions (API.md:49)
  - POST /admin/exceptions/{exception_id}/revoke (API.md:50)
  - POST /admin/devices/{device_id}/revoke (API.md:38)
  - GET /agent/updates/check (API.md:61)
- **Problem:** Missing 10 of ~20 endpoints means the spec is not usable for code generation. Security-critical operations (approval, revocation, exception creation) have no schema-validated contract.
- **Correction:** Add all missing endpoints to openapi.yaml with full schema, security, and error response definitions.
- **Verification test:** Run an OpenAPI linter; verify all endpoints in API.md Sections 3 and 4 have matching path entries with correct security schemes.

#### F-009 - policy.schema.json settings object is untyped - enables policy injection
- **Severity:** P1 - High
- **File:** schemas/policy.schema.json:29; openapi.yaml:440
- **Evidence:** Both the JSON Schema and OpenAPI Policy schema define settings as { "type": "object" } with no additionalProperties: false and no typed sub-schema per control_id. ENDPOINT_AGENT.md:41 requires "Policies must map to a finite set of typed controls with validated values."
- **Problem:** An attacker who can submit a crafted settings object could inject unexpected keys that a carelessly written adapter interprets as permission-grants, shell commands, or configuration overrides. The documented requirement cannot be satisfied while settings is an open object.
- **Correction:** For each control_id in the enum, add a typed settings sub-schema (oneOf/if-then discriminated by control_id) with additionalProperties: false and validated field types/ranges. Example for removable_storage: { "action": { "enum": ["deny", "read_only", "allow"] }, "device_classes": { "type": "array", "items": { "enum": ["USB_MSD", "CD_DVD"] } } }
- **Verification test:** Submit a policy with an unexpected key inside settings; verify API returns 400. Verify agent rejects a policy with settings fields not in the typed schema.

#### F-010 - No employee-facing privacy/telemetry notice document or process exists
- **Severity:** P1 - High
- **File:** SECURITY.md:63-67; ARCHITECTURE.md:18; ROADMAP.md Phase 0
- **Evidence:** SECURITY.md:63 says "Provide employee notice before enrollment." ROADMAP.md Phase 0 lists "Employee telemetry notice and data retention proposal" as a deliverable. Neither document nor template exists in the repository.
- **Problem:** In most jurisdictions, deploying monitoring software on employee computers without prior notice is a legal and regulatory risk. GDPR Article 13 obligations apply for EU/UK employees. The pilot cannot legally begin without this notice.
- **Correction:** Create EMPLOYEE_NOTICE.md containing: a plain-language description of what data is collected, how long it is retained, who can access it, how it is used in incidents, and a contact for questions. Add this as a required exit gate for Phase 0.
- **Verification test:** Legal or HR review signed off on the notice before any device enrollment.

---

### P2 - Medium

#### F-011 - Enrollment code entropy and at-rest hash algorithm unspecified
- **Severity:** P2 - Medium
- **File:** API.md:112; openapi.yaml:101; .env.example:21
- **Evidence:** Code minimum length is 20 characters (openapi.yaml:113). Maximum expiry allowed is 1800 seconds (openapi.yaml:101). No document specifies entropy requirement, character set, or hash algorithm for at-rest storage.
- **Problem:** If the implementation uses a low-entropy source or sequential generator, 1800 seconds is a large brute-force window. If stored in plaintext, database read access exposes codes.
- **Correction:** Add to API.md Section 8: (a) minimum entropy requirement (at least 128 bits), (b) character set (e.g., base32 or hex), (c) hash algorithm for at-rest storage (e.g., SHA-256), (d) maximum code lifetime for pilot (recommend 300 seconds, not 1800).
- **Verification test:** Verify the database stores only the hash of the code, not plaintext. Attempt 100 enrollment requests per minute; verify 429 returned.

#### F-012 - ControlResult safe_details has no schema - potential for sensitive data leakage
- **Severity:** P2 - Medium
- **File:** openapi.yaml:463; API.md:89
- **Evidence:** ControlResult.safe_details is a maxLength: 1000 string (openapi.yaml:463). No enforcement mechanism ensures the agent does not include file paths, user names, or registry values containing secrets.
- **Correction:** Define an allowlist of safe detail patterns in ENDPOINT_AGENT.md and add server-side pattern rejection for tokens, file content patterns, and email addresses.
- **Verification test:** Submit a ControlResult with safe_details containing a simulated token pattern; verify the API rejects it or redacts it before storage.

#### F-013 - Heartbeat interval vs. stale threshold creates a false-negative visibility window
- **Severity:** P2 - Medium
- **File:** .env.example:22-23; OPERATIONS.md Section 1
- **Evidence:** AGENT_HEARTBEAT_INTERVAL_SECONDS=300 (5 minutes), DEVICE_STALE_AFTER_SECONDS=1800 (30 minutes). A device can be offline or have its agent killed for up to 30 minutes before the server considers it stale, while the dashboard may show it as compliant.
- **Correction:** (a) Add a configurable DEVICE_WARN_AFTER_SECONDS threshold shorter than the stale threshold, (b) document the false-negative window explicitly in OPERATIONS.md, (c) require the dashboard to always show "Last verified: N minutes ago" next to any compliance status.
- **Verification test:** Kill the agent process; verify the dashboard shows last-seen time and transitions to stale after the threshold; verify it does not show compliant after the threshold.

#### F-014 - GET /admin/events has no cursor parameter in openapi.yaml
- **Severity:** P2 - Medium
- **File:** openapi.yaml:192-226; API.md:15
- **Evidence:** API.md:15 says "List endpoints use cursor pagination." The /admin/events path has device_id, event_type, from, to, and limit parameters but no cursor parameter. Without cursor pagination, large event volumes cannot be paged through.
- **Correction:** Add a cursor query parameter to /admin/events in openapi.yaml matching the pattern used by /admin/devices.
- **Verification test:** Generate 250 events, page through using cursor; verify all 250 are returned in sorted order.

#### F-015 - Agent update check endpoint missing from openapi.yaml
- **Severity:** P2 - Medium (also noted in F-008; called out separately due to security risk)
- **File:** API.md:61; openapi.yaml (entire file)
- **Evidence:** API.md:61 defines POST /agent/updates/check with the note "Never execute an unsigned update." No entry exists in openapi.yaml. The response shape for artifact_digest, signature_ref, and minimum_version is undefined.
- **Correction:** Add /agent/updates/check to openapi.yaml with a typed response schema referencing the agent_releases data-model fields.
- **Verification test:** Agent downloads update metadata, verifies digest and signature before applying. Submit a corrupted digest; verify agent aborts the update.

#### F-016 - DESIGN.md status vocabulary is not aligned with openapi.yaml device status enum
- **Severity:** P2 - Medium
- **File:** DESIGN.md:56-63; openapi.yaml:52,397
- **Evidence:** DESIGN.md Section 3 defines: compliant, noncompliant, stale, unknown, unsupported, partial. openapi.yaml DeviceSummary status enum: enrolled, compliant, noncompliant, stale, revoked, unknown. The values unsupported and partial from DESIGN.md are absent from the API schema. enrolled is in the API schema but not in DESIGN.md vocabulary.
- **Correction:** Align the vocabulary across DESIGN.md, API.md, and openapi.yaml. Either add partial and unsupported to the API enum or document that these are derived UI states computed from controls[] results.
- **Verification test:** API tests verify that a device with one unsupported control and all others enforced shows partial in the UI with correct per-control detail.

#### F-017 - No SIEM or external log sink integration is specified
- **Severity:** P2 - Medium
- **File:** DEPLOYMENT.md Section 7; SECURITY.md:32; DATA_MODEL.md Section audit
- **Evidence:** SECURITY.md:32 says "export logs to a protected sink where feasible." DEPLOYMENT.md Section 7 lists AUDIT_SINK_URL as configurable. No specific product or protocol is named.
- **Problem:** If the audit log is only in the same PostgreSQL database, a compromised control plane compromises the audit trail.
- **Correction:** Add at least one concrete recommended audit sink option to DEPLOYMENT.md (e.g., AWS CloudWatch Logs with resource policy, write-once S3 with object-lock), including the protection model.
- **Verification test:** Delete a row from admin_audit_events table; verify the external sink still contains the event.

#### F-018 - CONTRIBUTING.md does not link privacy notice or require legal review for telemetry changes
- **Severity:** P2 - Medium
- **File:** CONTRIBUTING.md:22; SECURITY.md:63
- **Evidence:** CONTRIBUTING.md:22 says "Employee-facing behavior and privacy notice updated if needed" without linking to a specific document or requiring legal review.
- **Correction:** Link the EMPLOYEE_NOTICE.md document (once created, see F-010) and specify that any PR expanding telemetry scope requires HR/legal review before merge.
- **Verification test:** Attempt to merge a PR adding a new telemetry field without updating the privacy notice; verify the PR checklist blocks it.

---

### P3 - Low / Documentation Quality

#### F-019 - README documentation map is incomplete
- **Severity:** P3 - Low
- **File:** README.md
- **Evidence:** CONTRIBUTING.md, OPERATIONS.md, and ROADMAP.md exist in the repository but are not listed in the README documentation map.
- **Correction:** Add CONTRIBUTING.md, OPERATIONS.md, and ROADMAP.md to the README documentation map.

#### F-020 - .env.example has no documentation for POLICY_VERIFYING_KEY_SET_URL
- **Severity:** P3 - Low
- **File:** .env.example:18
- **Evidence:** .env.example:18 defines POLICY_VERIFYING_KEY_SET_URL= with no comment explaining what format this URL returns (JWK Set? custom format?).
- **Correction:** Add a comment: "# URL returning the JSON Web Key Set (RFC 7517) used to verify policy signatures. Must be served over TLS with access controls."

#### F-021 - Mermaid diagram omits background worker trust boundary
- **Severity:** P3 - Low
- **File:** ARCHITECTURE.md:70-92
- **Evidence:** The diagram shows API --> Worker but the worker's connections to the database, external alert sinks, and the policy-signing service are not shown.
- **Correction:** Extend the diagram to show Worker --> DB, Worker --> ExternalAlertSink, and Worker --> SigningService as separate edges with labels.

#### F-022 - Python and Node versions are not pinned anywhere
- **Severity:** P3 - Low
- **File:** DEPLOYMENT.md; README.md
- **Evidence:** The stack mentions FastAPI (Python) and React (Node/npm) but no version constraints appear in any document. No pyproject.toml, package.json, or requirements.txt exists.
- **Correction:** Add a "Runtime versions" note to DEPLOYMENT.md indicating minimum Python (e.g., 3.12+) and Node (e.g., 20 LTS) versions required.

#### F-023 - Detailed sequence diagrams for enrollment, policy cycle, and agent update are absent
- **Severity:** P3 - Low
- **File:** diagrams/README.md; ARCHITECTURE.md
- **Evidence:** Only one Mermaid diagram (component topology) exists. Detailed sequence diagrams for enrollment, policy retrieval, and control verification are absent, making agent trust interactions hard to verify.
- **Correction:** Add sequence diagrams in ARCHITECTURE.md for: (1) device enrollment, (2) policy retrieval and application cycle, (3) control verification and result reporting, (4) agent update flow.

---

## D. Architecture and Trust-Boundary Review

### Correct Component Responsibilities

The documentation correctly separates:
- **Control plane:** metadata, policy definitions, device registry, events, audit - NOT source code
- **Agent:** orchestration of OS controls, status reporting - NOT content interception
- **DLP adapter:** status wrapper around an external provider - correctly disclaimed

### Trust Boundary Gaps Found

1. **Background worker trust boundary is undefined.** The worker processes events, sends alerts, and may invoke the signing service. Its database access scope, network egress rules, and authentication to external sinks are not specified. The worker should have its own least-privilege DB role distinct from the API.

2. **Agent-to-OS boundary is one-way in the diagram but bidirectional in practice.** The agent reads back the effective state of OS controls. This read-back path is the critical enforcement verification step; it should be shown explicitly as a separate labeled edge.

3. **Employee-to-Agent trust boundary is missing from the diagram entirely.** The employee can see the agent UI and interact with any agent tray interface. The agent must not expose sensitive data or privileged operations to the user-mode account.

4. **Optional Git provider is shown without trust qualification.** The diagram shows "Local <--> Git" with "Authenticated Git, only if approved" but does not show that the Git provider is outside the WorkGuard trust domain and that WorkGuard cannot enforce Git access controls - it can only revoke access as an integration.

### Corrected Architecture Diagram

`mermaid
flowchart TB
  Admin[Administrator browser]
  IdP[OIDC identity provider / MFA]
  API[WorkGuard FastAPI - Least-privilege API role]
  DB[(PostgreSQL - Two DB roles: api-rw and worker-rw)]
  Worker[Background worker - Least-privilege worker role]
  LogSink[Append-only external audit sink]
  SignSvc[Policy signing service / KMS - HSM-backed]
  Agent[Signed Windows service - SYSTEM / restricted DACL]
  OS[Windows native security controls - Group Policy / MDE]
  Employee[Employee user-mode process]
  DLP[Supported endpoint DLP or SWG - external product]
  Local[(Local source code and work files)]
  Git[Optional private Git provider - external trust domain]

  Admin -->|HTTPS + OIDC bearer| API
  Admin -->|OIDC auth| IdP
  IdP -->|token validation| API
  API <-->|api-rw role| DB
  API --> Worker
  Worker -->|worker-rw role| DB
  Worker -->|append-only write| LogSink
  API -->|sign request| SignSvc
  SignSvc -->|signed envelope| API
  Agent <-->|mTLS + device cert over untrusted network| API
  Agent -->|Apply policy settings| OS
  OS -->|Read-back verification| Agent
  Agent <-->|Status and events only - no file content| DLP
  OS -->|enforced native controls| Local
  Employee -->|user-mode read| Local
  Employee -->|read agent status only| Agent
  Local <-->|Authenticated push if approved| Git
`

### Residual Risk Summary

| Risk | Category | WorkGuard reduces | WorkGuard cannot prevent |
|---|---|---|---|
| USB copy | Technical | Yes - native policy blocks write | Device boot from another OS; hardware extraction |
| Browser upload | Technical | Partially - requires DLP integration | Browser profiles not in DLP scope; DLP bypass via proxy |
| Screen photography | Physical | No | Cannot be prevented technically |
| Manual transcription | Physical | No | Cannot be prevented technically |
| Local admin bypass | Technical | Partial - service DACL, drift detection | Full local-admin access defeats most user-mode controls |
| Offline exfiltration | Technical | Partial - last-applied policy remains | No heartbeat means no central visibility |
| Insider with legitimate access | Procedural | Audit trail, exceptions | Any authorized viewer can copy what they see |

---

## E. API and Data-Model Audit

### Missing or Incomplete Endpoints

| Missing Endpoint | Criticality | Notes |
|---|---|---|
| GET /admin/policies/{policy_id} | High | Cannot view policy details; required for approval workflow |
| PATCH /admin/policies/{policy_id} | High | Cannot edit draft policies via machine-readable contract |
| POST /admin/policies/{policy_id}/submit | High | Cannot advance policy lifecycle |
| POST /admin/policies/{policy_id}/approve | Critical | Second-person approval gate has no API spec; two-person rule cannot be tested |
| POST /admin/policies/{policy_id}/rollback | High | Emergency rollback has no schema |
| GET /admin/audit-events | High | Administrator accountability trail missing from spec |
| POST /admin/devices/{device_id}/revoke | High | Device revocation missing from spec |
| POST /admin/exceptions | Medium | Exception creation has no schema |
| POST /admin/exceptions/{exception_id}/revoke | Medium | Exception revocation has no schema |
| GET /agent/updates/check | High | Agent update flow undefined |

### Authorization Coverage Gaps

| Endpoint | Issue |
|---|---|
| /admin/events | No organization-scope filter parameter; a multi-tenant deployment could expose one tenant's events to another tenant's auditor if not enforced server-side |
| /admin/devices | No organization_id filter documented; same multi-tenant concern |
| /agent/policy-results | Policy referenced by policy_version integer only, not policy_id + version; a device could submit results for another device's policy version if version numbers are shared across policies |
| /agent/events:batch | No per-device rate limit distinct from global rate limit; one compromised agent can flood the event queue |

### Data-Model Issues

| Entity | Issue |
|---|---|
| policy_assignments | target_type and target_id are underspecified - no valid target type enum defined (Device? Group? Organization?) |
| control_results | desired_state and observed_state are untyped; same injection risk as settings (see F-009) |
| security_events | safe_metadata is untyped; same leakage risk as F-012 |
| agent_releases | No minimum OS build or edition constraint field; an old agent could report compatibility with editions it does not support |
| device_credentials | No credential_type field; cannot distinguish mTLS cert from other future credential forms |

### Schema Alignment Issues

| Discrepancy | Files |
|---|---|
| policy.schema.json requires schema_version, policy_id, policy_version, name, controls but NOT rollout_mode. openapi.yaml Policy schema (line 421) marks rollout_mode as required. | policy.schema.json:8 vs openapi.yaml:421 |
| DESIGN.md status enum includes partial and unsupported; openapi.yaml DeviceSummary status enum does not | DESIGN.md:56-63 vs openapi.yaml:397 |
| API.md documents Idempotency-Key header but it is required: false in openapi.yaml; for enrollment-code creation it should be strongly recommended | openapi.yaml:364 |

---

## F. Security Verification Plan

All tests use harmless synthetic data on a dedicated test device. Each test requires explicit pass/fail evidence before the gate is marked cleared.

### Pre-implementation Security Gates (Phase 0)

| Test ID | Scenario | Preconditions | Test action | Expected result | Evidence required |
|---|---|---|---|---|---|
| SEC-001 | Signing algorithm documented | Signing spec written | Review spec document | Algorithm, encoding, and key format all specified | Document review checklist signed |
| SEC-002 | PKI design documented | PKI spec written | Review spec document | CA, key storage, renewal, and revocation all specified | Document review checklist signed |
| SEC-003 | Windows edition matrix complete | Matrix written | Verify each control against Microsoft official docs | All controls available on declared editions | Microsoft docs citation per row |

### Control-Plane API Security (Phase 1)

| Test ID | Scenario | Test action | Expected result | Evidence |
|---|---|---|---|---|
| SEC-004 | Unauthenticated API access | Call any admin endpoint without a token | 401 returned; no data leaked | API test log |
| SEC-005 | Cross-device policy read | Device A calls /agent/policies/current with Device B device_id injected | 403 returned | API test log |
| SEC-006 | Cross-tenant device read | Org A admin calls /admin/devices | Only Org A devices returned | API test log |
| SEC-007 | Single-approver publish blocked | User A submits and approves own policy | Publish returns 403 | API test log + audit event |
| SEC-008 | Enrollment code single-use | Use same code twice | Second use returns 401 or 400 | API test log |
| SEC-009 | Enrollment rate limit | Attempt 20 enrollment requests in 60 seconds | 429 returned after threshold | API test log |
| SEC-010 | Audit event redaction | Submit request with authorization token in body | Token does not appear in logs or error responses | Log scan test |

### Agent and Endpoint Security (Phase 2)

| Test ID | Scenario | Test action | Expected result | Evidence |
|---|---|---|---|---|
| SEC-011 | Policy signature tampering | Flip one byte in canonical bytes before delivery | Agent rejects policy; last safe policy remains active | Agent event log + server event |
| SEC-012 | Policy version downgrade | Deliver policy v3 when v5 is applied | Agent rejects downgrade; event emitted | Agent log |
| SEC-013 | Expired policy | Deliver policy with expiry 10 seconds in the past | Agent rejects; last safe policy remains | Agent log |
| SEC-014 | Device target mismatch | Deliver policy for Device B to Device A | Agent rejects; event emitted | Agent log |
| SEC-015 | Service stop by standard user | Standard user runs sc stop WorkGuardAgent | Access denied | Windows event log |
| SEC-016 | USB storage block | Insert USB drive; attempt to write a file | Write fails at OS level; alert generated | Windows event log + dashboard event |
| SEC-017 | Agent offline behavior | Disconnect network for 35 minutes | Last-applied controls remain active; dashboard shows stale | Agent local log + dashboard |
| SEC-018 | Revoked device reconnects | Revoked device attempts heartbeat | 401 returned; sensitive access revoked | API log + dashboard |
| SEC-019 | Agent update with corrupted digest | Corrupt the update package | Agent verifier rejects; no update applied | Agent log |
| SEC-020 | No source code in heartbeat | Inspect heartbeat payload | No file paths, content, or directory listings present | Network capture + payload audit |

### Transfer Control Verification (Phase 3 and 4)

| Test ID | Channel | Expected enforcement | Evidence |
|---|---|---|---|
| DLP-001 | USB mass storage | OS-level write denied; event in dashboard | Windows event ID + dashboard alert |
| DLP-002 | Browser upload via Chrome | Browser shows block; provider event generated | Provider management console + dashboard |
| DLP-003 | Browser upload via Edge | Same | Same |
| DLP-004 | Desktop cloud sync client | File not synced; event generated | Provider event or network block log |
| DLP-005 | Personal webmail | Attachment blocked or email blocked | Provider event |
| DLP-006 | Desktop email client | Same | Same |
| DLP-007 | HTTPS Git push to personal GitHub | Push rejected; event generated | Provider event or network block |
| DLP-008 | SSH Git push | Connection blocked | Firewall log |
| DLP-009 | Bluetooth file transfer | Transfer blocked | Windows event or provider event |
| DLP-010 | SMB network share | Copy blocked | Firewall log |
| DLP-011 | Virtual printing to PDF | Controlled or blocked | Provider event |
| DLP-012 | Alternate browser profile | Result documented; if unknown, must state so explicitly | Test report with explicit limitation |
| DLP-013 | Personal VPN or proxy tool | Result documented; if unknown, must state so explicitly | Test report with explicit limitation |

Each DLP test must record: OS build, browser/app version, DLP provider version, policy version, result, and explicit limitations.

---

## G. Prioritized Documentation Correction Plan

Items marked [BLOCKS CODING] must be done before implementation starts. Items marked [BLOCKS PILOT] must be done before a pilot.

| Priority | Action | File(s) | Blocks |
|---|---|---|---|
| 1 | Write signing algorithm and canonical encoding specification (F-001) | New: SIGNING_SPEC.md or ARCHITECTURE.md Section 9 | CODING |
| 2 | Write PKI design for device credential issuance and renewal (F-002) | ENDPOINT_AGENT.md new section, ARCHITECTURE.md Section 3.3 | CODING |
| 3 | Add all missing endpoints to openapi.yaml (F-008) | openapi.yaml | CODING |
| 4 | Add typed settings sub-schemas per control_id (F-009) | schemas/policy.schema.json, openapi.yaml | CODING |
| 5 | Write Windows edition and licensing matrix (F-003) | ENDPOINT_AGENT.md Section 5 | CODING |
| 6 | Clarify rollback versioning semantics (F-007) | API.md Section 4, ARCHITECTURE.md Section 5 | CODING |
| 7 | Create EMPLOYEE_NOTICE.md template (F-010) | New file | PILOT |
| 8 | Create CHANNEL_COVERAGE.md (F-004) | New file | PILOT |
| 9 | Add cost/licensing section to DEPLOYMENT.md (F-006) | DEPLOYMENT.md | PILOT |
| 10 | Specify service DACL and evaluate PPL (F-005) | ENDPOINT_AGENT.md Section 6 | PILOT |
| 11 | Add cursor parameter to /admin/events (F-014) | openapi.yaml | Phase 2 |
| 12 | Add /agent/updates/check to openapi.yaml (F-015) | openapi.yaml | Phase 2 |
| 13 | Align device status enum across DESIGN.md, API.md, openapi.yaml (F-016) | DESIGN.md Section 3, openapi.yaml | Phase 2 |
| 14 | Add SIEM/audit sink concrete recommendation (F-017) | DEPLOYMENT.md Section 7 | PILOT |
| 15 | Add entropy and hash spec for enrollment codes (F-011) | API.md Section 8 | Phase 2 |
| 16 | Add safe_details allowlist specification (F-012) | ENDPOINT_AGENT.md Section 4, API.md Section 6 | Phase 2 |
| 17 | Document stale-window false-negative window (F-013) | OPERATIONS.md Section 1, DESIGN.md Section 6 | Phase 2 |
| 18 | Add privacy-notice link to CONTRIBUTING.md (F-018) | CONTRIBUTING.md | Phase 2 |
| 19 | Add CONTRIBUTING.md, OPERATIONS.md, ROADMAP.md to README map (F-019) | README.md | P3 |
| 20 | Add POLICY_VERIFYING_KEY_SET_URL comment (F-020) | .env.example | P3 |
| 21 | Extend Mermaid diagram with worker/employee/signing-service edges (F-021) | ARCHITECTURE.md | P3 |
| 22 | Pin Python, Node, .NET versions in DEPLOYMENT.md (F-022) | DEPLOYMENT.md | P3 |
| 23 | Add enrollment and policy-cycle sequence diagrams (F-023) | ARCHITECTURE.md | P3 |

### Canonical Source of Truth for Duplicated Requirements

| Requirement | Canonical source | Derivative documents |
|---|---|---|
| Policy signature format | SIGNING_SPEC.md (to be created) | ARCHITECTURE.md, SECURITY.md, API.md, ENDPOINT_AGENT.md |
| PKI / device credential | ENDPOINT_AGENT.md new section | ARCHITECTURE.md, API.md |
| Control status vocabulary | DESIGN.md Section 3 | openapi.yaml, API.md |
| Event taxonomy | SECURITY.md Section 4 | DATA_MODEL.md, TESTING.md, openapi.yaml |
| Policy lifecycle states | ARCHITECTURE.md Section 5 | API.md, openapi.yaml PolicySummary, DESIGN.md |
| Enrollment code security properties | API.md Section 8 | openapi.yaml, ENDPOINT_AGENT.md |

---

## H. Final Scorecard

| Dimension | Score | Evidence for score |
|---|---|---|
| Requirements coverage | 62 / 100 | 10/20 requirements are fully covered. USB, app control, DLP, tamper resistance, and cost are partial or missing detail. Honest disclaimers are good but do not compensate for missing R10/R11 channel-coverage requirements. |
| Architectural consistency | 74 / 100 | Strong: metadata/content separation, honest DLP claims, policy lifecycle, multi-status vocabulary. Penalized for: missing worker trust boundary, undefined PKI, unspecified signing algorithm, DESIGN.md/openapi.yaml status enum mismatch, and rollback ambiguity. |
| Security design quality | 70 / 100 | Excellent posture statements: no shared secrets, no kernel drivers, honest residual risks, two-person approval, signed policies, append-only audit. Penalized heavily for F-001 (signing algorithm absent - the most critical gap), F-002 (PKI undefined), and F-009 (untyped settings). |
| Technical feasibility | 78 / 100 | Architecture is realistically buildable for a small team. Tech stack is well-suited. Deducted for: no Windows edition matrix (some controls may not be available), no DLP vendor selection, and undefined PKI (Phase 2 is unbuildable until F-002 is resolved). |
| API and data-model completeness | 48 / 100 | The openapi.yaml covers fewer than half the documented endpoints. Missing: approval, rollback, audit-events, exceptions, device revocation, update check. settings is untyped. Status enum is misaligned. This is the weakest dimension. |
| Testing readiness | 58 / 100 | TESTING.md has good acceptance-matrix structure and correctly calls out "browser error is not proof." Penalized for: no per-channel DLP test matrix document, no concrete pass/fail evidence requirements for USB and app-control tests, no signing algorithm to test against. |
| Deployment readiness | 45 / 100 | Deployment guide covers structure well. Penalized heavily for: no cloud provider named, no cost estimates, no database migration tool specified, no HSM product named, no DLP vendor named, no code-signing certificate process, and no backup-restoration SLA. |
| Overall documentation quality | 68 / 100 | Writing quality is high: consistent terminology, good caveats and non-goals, no false security claims, actionable operations runbooks. Penalized for: 10 missing openapi.yaml endpoints, unresolved open design decisions that block coding, absent privacy notice, missing channel-coverage document, and status vocabulary misalignment. |

---

## I. Release Gate

### Gate 1: Before Coding Begins

1. F-001 - Signing algorithm, canonical encoding, and envelope specification written and reviewed
2. F-002 - PKI design for device credentials: CA selection, key storage, renewal, revocation
3. F-008 - All API endpoints added to openapi.yaml (especially the approval and revocation flows)
4. F-009 - Typed settings sub-schemas defined for all six control_id values
5. F-003 - Windows edition and licensing matrix completed and verified against Microsoft documentation
6. F-007 - Rollback versioning semantics made unambiguous in API.md and ARCHITECTURE.md
7. Phase 0 ROADMAP deliverables signed off: device inventory, existing licensing check, pilot success criteria

### Gate 2: Before a One-Laptop Pilot Begins

1. All Gate 1 items resolved
2. F-010 - Employee privacy and telemetry notice reviewed by legal/HR and ready for delivery
3. F-004 - Channel-coverage matrix (CHANNEL_COVERAGE.md) written with each channel marked blocked/unknown/out-of-scope
4. F-006 - Cost and licensing estimate reviewed and approved by management
5. F-005 - Windows service DACL specified and tested on the pilot device; standard-user stop attempt fails
6. SEC-011 through SEC-018 all pass on the pilot device
7. Policy rollback verified end-to-end on the pilot device (see F-007)
8. Backup and database restore tested at least once
9. Responsible disclosure contact and response process documented

### Gate 3: Before Production Rollout Begins

1. All Gate 2 items resolved
2. DLP vendor selected, integrated, channel coverage tested and documented per DLP-001 through DLP-013
3. External/independent security review of the agent binary and installer
4. HSM-backed signing key in production; signing key rotation procedure tested
5. Append-only external audit sink deployed and verified (F-017)
6. Offboarding drill completed; offboarding checklist verified against OPERATIONS.md Section 6
7. Incident response tabletop completed; incident owner named
8. All P0 and P1 findings resolved and verified
9. Management formally accepts documented residual risks in writing
10. Gradual rollout plan with rollback criteria documented and approved

---
*End of WorkGuard Architecture and Documentation Audit Report*
