# WorkGuard Testing and Acceptance Plan

## 1. Test stages

- Unit tests: policy parsing, state machine, RBAC decisions, version validation and event schemas.
- API integration tests: PostgreSQL, authentication, pagination, rate limits and audit writes.
- Windows integration tests: policy apply/read-back, service ACLs, update verification and offline behavior.
- Security tests: object authorization, policy signature, replay/downgrade, enrollment brute force and secret leakage.
- Pilot acceptance tests: real-world developer workflow and transfer controls using harmless files.

## 2. Minimum acceptance matrix

| Scenario | Expected result | Evidence |
|---|---|---|
| Enrolled device checks in | Device identity validated; heartbeat persisted | API test and device record |
| Unknown device calls agent API | Denied | 401/403 and security log |
| Device reads another device's policy | Denied | Authorization regression test |
| Expired enrollment code reused | Denied | API test and audit event |
| Policy signature altered | Agent rejects policy; last safe policy remains | Agent log and server event |
| Old policy version replayed | Agent rejects downgrade | Automated test |
| USB storage write/read attempt | Matches approved native/provider policy | Test record for each supported OS build/device class |
| Unapproved app launch | Blocked only after enforcement policy is validated | Provider/Windows event and test artifact |
| DLP upload to a blocked destination | Blocked for a documented supported app/browser/channel | Test matrix with provider event |
| Upload from an untested alternate channel | Coverage documented as unknown until tested | Gap recorded; do not claim block |
| Agent offline | Last-known controls remain active; console status becomes stale after threshold | Network-disconnect test |
| Agent update modified | Signature/digest verification fails | Installer/update test |
| Policy enforcement fails | Status is failed/partial, not compliant | Dashboard and event record |
| High-impact policy has one approver | Publish rejected when dual approval required | API test |
| Revoked device reconnects | Authentication rejected; sensitive access revoked where integrated | Revocation test |
| Database restore | Metadata/audit recover within target | Restore report |
| Logs contain secret markers | No secrets appear | Automated log redaction test |

## 3. Leak-prevention validation matrix

Test each transfer channel separately:

- USB mass storage and other in-scope removable media.
- Browser uploads to each restricted cloud destination.
- Desktop cloud-sync clients.
- Webmail and desktop email clients.
- Git push over HTTPS and SSH to approved and personal repositories.
- Chat/messaging attachments.
- Bluetooth file transfer and nearby sharing.
- SMB/network shares.
- Printing and virtual printing/PDF output.
- Clipboard copy/paste to external applications.
- Screenshots and screen recording, where supported.
- VPN/proxy and alternative browser profiles.

Use synthetic content with unique markers. Verify both the user-visible outcome and the authoritative control/provider event. A browser error by itself is not proof of enforced DLP. Record OS build, application/version, provider/version, policy version, result and limitations.

## 4. Test environment safety

- Use dedicated test devices and non-production repositories.
- Do not test destructive containment, lockout or policy rollout on an employee's only work device.
- Start in audit mode where supported.
- Keep recovery credentials available to authorized IT staff.
- Have rollback and device recovery procedures before enforcing policies.

## 5. Release criteria

- All critical tests pass on each supported platform version.
- No unresolved critical security defect.
- All transfer controls have documented coverage/limitations.
- No source-code content is sent to the control plane.
- High-impact actions are audited and require approvals.
- Agent update and policy rollback verified.
- The company accepts residual risk and approves employee notice before pilot.
