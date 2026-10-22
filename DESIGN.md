# WorkGuard Product and UX Design

## 1. Product roles

- **Security administrator:** enrolls/revokes devices, configures and approves policies, investigates events.
- **IT operator:** views device health, resolves failed controls and coordinates updates; cannot publish high-impact policy alone unless delegated.
- **Auditor:** read-only access to policies, changes and events; cannot change enforcement.
- **Employee:** sees agent health, current company policy status, last successful check-in and support instructions; cannot disable managed controls.

## 2. Primary screens

### Overview dashboard
Show:
- Managed devices, compliant devices, stale devices and devices with failed controls.
- Policies in draft, audit, enforcement, partial failure and rollback states.
- Recent security events grouped by severity.
- Last data update and any outage banner.

Do not show a single green "Protected" badge if only one control has been verified. Display per-control coverage and data freshness.

### Device detail
Fields:
- Device ID and display name; assigned employee; OS version/edition; agent version.
- Last seen, enrollment status, compliance status.
- Required controls and verified state: USB, application control, disk encryption, endpoint protection, DLP integration and firewall/network configuration.
- Policy version desired vs. policy version reported as applied.
- Recent events and actions (sync, request diagnostics, quarantine/revoke sensitive access).

The UI must distinguish `desired`, `reported`, and `verified` states.

### Policy editor
- Select from reviewed templates rather than free-form scripts.
- Show target scope, platforms, expected impact, dependencies, current coverage, supported limitations, rollback option and test results.
- Require a reason for edits.
- Use staged rollout: lab group → pilot group → remaining devices.
- High-impact policy requires second-person approval.
- Never remotely execute arbitrary shell commands from the portal as a policy mechanism.

### Exceptions
Each exception includes: policy/control, device or employee scope, reason, requester, approver, start, expiry, compensating control and audit event. No permanent exception without an explicit risk review.

### Security events
- Filter by device, user, event class, policy, severity, time and source provider.
- Show evidence source, what the provider actually reported, response status and owner.
- Avoid displaying raw secrets, source file contents or unnecessary employee data.

### Employee agent view
Show:
- "Company security active" plus per-control status and latest check-in.
- Meaningful guidance when action is blocked and link to request an exception.
- Privacy notice, help link and restart/update instructions.
- Do not expose signing keys, policy secrets or other employees' data.

## 3. Status vocabulary (F-016)

### Canonical API/DB Device Statuses
- `enrolled`: Device identity registered, awaiting initial policy application and control read-back.
- `compliant`: All required controls assigned by the active policy are verified active and fresh.
- `noncompliant`: One or more required controls failed, drifted, or failed read-back verification.
- `stale`: No heartbeat received within `DEVICE_STALE_AFTER_SECONDS` (default: 30 minutes). Revokes cached compliance claims.
- `revoked`: Device identity or enrollment has been revoked by an administrator; access blocked.
- `unknown`: Device state cannot be assessed due to missing telemetry or uninitialized provider.

### Derived UI Presentation States (Computed from Per-Control Results)
- `partial`: Some required controls are enforced, but others report `partial` or `unsupported`.
- `unsupported`: The platform, OS version, or Windows edition cannot enforce one or more required controls.

### Freshness and Visibility Rules (F-013)
- "Unknown", "warning", and "stale" are **never** rendered with green/compliant badges.
- Every device row and detail header **must display** `Last verified: [N minutes ago]` (or relative time with hoverable UTC timestamp) directly adjacent to the status badge.
- If last check-in exceeds `DEVICE_WARN_AFTER_SECONDS` (10 minutes), display an amber warning chip indicating stale telemetry risk.

## 4. Accessibility and usability

- Keyboard-navigable controls, accessible labels, adequate contrast and clear focus states.
- Use confirmation and a typed reason for destructive or high-impact actions.
- Explain security failures in actionable terms without exposing exploit details.
- Show time zone and timestamps consistently.
- Provide export formats that avoid including secrets or personal file contents.

## 5. Design language

Use a restrained enterprise security visual language: neutral background, clear tables, severity color only for meaningful event status, and no decorative success badges for ordinary sections. Every data panel should disclose when it last updated.

## 6. Important UI safety rules

- A button labelled **Block USB** must not show success until the endpoint reports verified enforcement.
- A policy marked `published` is not necessarily `enforced`.
- When a device is offline, show the last-known status and its timestamp, not a current claim.
- Do not offer a feature that suggests universal upload blocking unless its integration and tested scope really provide that coverage.
