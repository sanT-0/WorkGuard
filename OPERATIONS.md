# WorkGuard Operations Runbooks

## 1. Device shows warning or stale

### Detection Window and False-Negative Visibility Gap (F-013)
Under default operational settings:
- `AGENT_HEARTBEAT_INTERVAL_SECONDS`: 300s (5 minutes)
- `DEVICE_WARN_AFTER_SECONDS`: 600s (10 minutes — 2 missed check-ins)
- `DEVICE_STALE_AFTER_SECONDS`: 1800s (30 minutes — 6 missed check-ins)

If an agent is stopped, killed by a local administrator, or disconnected from the network, the control plane cannot immediately distinguish disconnection from tampering. This creates an inherent visibility window of up to 10 minutes before warning and up to 30 minutes before stale transition.
**Mandatory operational rule:** Never assume an endpoint is compliant simply because it was compliant 20 minutes ago. The dashboard must always display `Last verified: [timestamp / N minutes ago]` alongside compliance state. When `DEVICE_WARN_AFTER_SECONDS` is exceeded, the device status transitions to an amber warning indicator, and when `DEVICE_STALE_AFTER_SECONDS` is exceeded, the server automatically updates the device status to `stale` and revokes cached compliance claims.

### Runbook Steps
1. Check `last_seen_at` and determine if the laptop is in transit or expected to be offline.
2. Confirm agent service state (`sc query WorkGuardAgent`) and network/TLS reachability using approved remote support procedures.
3. If the device reaches `stale`, the control plane marks it `stale` (non-compliant) and triggers conditional-access integration to suspend company Git repository and intranet tokens.
4. If tampering is suspected (e.g., service was manually disabled or uninstalled), open a security incident under Runbook 3.
5. Record incident resolution and verify fresh policy read-back after the agent reconnects.

## 2. Control reports failed or unsupported

1. Identify the control/provider, Windows edition/build, agent version and policy version.
2. Review safe diagnostic data and supported vendor/Windows documentation.
3. Do not manually mark the control successful.
4. If the control is required, restrict sensitive access until fixed or an approved compensating control is in place.
5. Test correction on a pilot device before rolling out widely.

## 3. Suspected unauthorized transfer

1. Preserve relevant endpoint/provider and central audit records.
2. Confirm what the control actually observed; distinguish an attempted transfer, blocked transfer and confirmed disclosure.
3. Revoke compromised sessions/credentials and limit repository access if appropriate.
4. Engage the designated security/HR/legal owner under company policy.
5. Avoid collecting unrelated personal data. Record the decision and evidence source.

## 4. Policy rollout failure

1. Halt further rollout.
2. Identify the last known-good signed policy version.
3. Obtain required approval for rollback.
4. Publish the prior safe version through the signed rollback path.
5. Verify endpoint read-back and normal developer workflows.
6. Document cause and add a regression test.

## 5. Administrator or signing credential compromise

1. Disable the affected admin identity and revoke active sessions.
2. Suspend policy publishing if signing integrity is uncertain.
3. Rotate/revoke affected credentials and signing keys using the documented key-management procedure.
4. Review audit logs for policy edits, approvals, device revocations and exports.
5. Revalidate all active signed policy artifacts before resuming publishing.
6. Follow the incident response process and document scope.

## 6. Employee offboarding

1. Disable identity-provider account and revoke sessions.
2. Revoke device credential or device enrollment when company policy calls for it.
3. Remove repository, package registry, cloud and CI access.
4. Rotate or revoke personal tokens and secrets accessible to the user; prefer short-lived credentials to reduce this task.
5. Handle laptop return, backup and local data deletion through the approved asset process.
6. Confirm all actions in an audit record.

## 7. Routine operations cadence

- Daily/automated: failed control, stale device, service health and security alert review.
- Weekly: exception expiry, overdue updates, policy drift and alert tuning review.
- Monthly: access review, service/agent patch review, backup verification and dependency scan review.
- Quarterly: restore exercise, offboarding drill, incident tabletop and transfer-channel retest after major OS/provider updates.
