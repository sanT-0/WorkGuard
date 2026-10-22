# WorkGuard Threat Model

## 1. Assets

- Company source code and intellectual property (primarily on endpoints and optional Git host).
- Device and administrator credentials.
- Policy-signing private key and signed policy artifacts.
- Endpoint agent binaries/update pipeline.
- Device inventory, event records, employee identifiers and administrator audit trail.
- Availability and integrity of endpoint controls.

## 2. Trust boundaries

1. Administrator browser → control API.
2. Agent → control API over an untrusted home/public network.
3. Control plane → database, queue, logging and secret manager.
4. Agent user-mode service → privileged Windows policy interfaces.
5. Laptop → external browser/cloud/email/Git/network destinations.
6. Optional Git provider → developer laptop and CI jobs.

## 3. Adversaries and assumptions

- Opportunistic attacker who steals an employee password or laptop.
- Malicious external party who attempts API abuse or credential theft.
- Employee or contractor attempting an unauthorized transfer.
- Compromised developer tool, dependency or update package.
- Administrator error or malicious over-privileged administrator.
- Malware running with the employee's permissions.

Assume a local administrator or physically present person may bypass some user-mode restrictions. The system should detect tampering and reduce exposure but must not claim absolute prevention against a fully compromised endpoint.

## 4. Threats and mitigations

| Threat | Primary mitigations | Residual risk / validation |
|---|---|---|
| Stolen employee password | MFA, SSO, conditional access where available, session revocation | Phishing-resistant MFA preferred; test recovery flow |
| Stolen laptop | Disk encryption, secure boot, lock screen, remote credential revocation | Data exposed if already unlocked/compromised; test recovery key process |
| Copy to USB | Native/managed device-control policy, verification and alerts | Test all supported media classes; device categories vary |
| Upload to personal cloud/email | Supported endpoint DLP, browser/secure-web-gateway controls, restricted apps | Coverage varies by app/browser/version; maintain an explicit matrix |
| Push to personal Git | Repository credentials, authorized remotes, private repo permissions and DLP/network controls | Git over alternative protocols/hosts needs testing; local copy remains readable |
| Employee disables agent | Standard-user account, protected service configuration, App Control, drift detection | Local administrators/physical control can still defeat some controls |
| Fake/tampered policy | Digital signature, schema validation, anti-replay/version checks | Signing key compromise is high impact; protect/revoke key |
| Malicious agent update | Signed build pipeline, review, artifact hashes, staged rollout, anti-rollback | CI/signing compromise; isolate release signing |
| API object authorization flaw | Server-side object scope, tenant isolation tests, least privilege | Continuous security testing required |
| Event/log deletion | Restricted append-only roles, separate log sink, audit of audit access | No database-only design is inherently immutable |
| Admin misconfiguration | Two-person approval, audit, canary rollout, rollback | Emergency break-glass workflow needs monitoring |
| Malicious dependency | Lockfiles, SBOM, scanning, pinned/approved sources, signed builds | Dependency ecosystem risks remain |
| Screenshot/photo/manual transcription | Watermark where supported, access minimization, policy and response | Cannot be guaranteed technically prevented on a user-visible local screen |
| Control-plane outage | Local native policies remain active, cached signed policy, backups | Central visibility may be stale; make dashboard state explicit |

## 5. Abuse cases to test

- Agent tries to fetch another device's policy by changing an ID.
- User replays an old policy or changes its JSON after signing.
- Enrollment code is reused or brute-forced.
- Agent submits a fake `compliant` result while a required control is disabled.
- Admin publishes without the required approver.
- User attempts to downgrade the agent or reinstall an old version.
- API returns tokens/secrets in logs or error traces.
- A personal sync client uploads files through a channel absent from DLP coverage.
- Local administrator disables a control; the system should detect/report this where possible and mark the device noncompliant rather than claim prevention.

## 6. Highest-risk decisions

Before production, resolve how the product covers personal cloud uploads, webmail, browser alternate profiles, personal Git, VPN/proxy tools, removable media, printers and unmanaged endpoints. A control that was not tested must be documented as unknown, not secure.
