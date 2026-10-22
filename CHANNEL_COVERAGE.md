# WorkGuard DLP Channel Coverage Matrix

> **Status:** Living document. Every row must be reviewed and re-tested after major OS
> updates, browser updates, or DLP provider changes. A channel listed as **Unknown** must
> not be represented as protected in the dashboard or in any communication to employees or
> management.
>
> **Audit date of this version:** 2026-10-22
> **Next mandatory review:** Before the Phase 4 exit gate and before production rollout.

---

## 1. Purpose

This document records which data-transfer channels WorkGuard explicitly protects, which
channels are out of scope, and which channels have not yet been tested. It is the canonical
answer to the question "what does WorkGuard actually prevent?"

Employees and administrators must be told only what is listed in the **Blocked (verified)**
section. Channels marked **Unknown** or **Out of scope** must be communicated as residual
risks requiring compensating controls and procedural policy.

---

## 2. How to read this document

**Status values:**

| Status | Meaning |
|---|---|
| **Blocked — verified** | The control has been implemented, tested on each listed OS build and application version, and produces an authoritative provider event. The test record is linked or filed. |
| **Blocked — untested** | A control mechanism exists and is configured, but end-to-end testing on real devices and application versions has not been completed. Must not be communicated as verified. |
| **Allowed by exception** | This channel is permitted for defined use cases; exceptions are scoped, time-limited, approved, and audited. |
| **Allowed — legitimate workflow** | This channel carries legitimate business traffic (e.g., approved Git host) and is explicitly permitted. Access control and auditing are in place through the approved service, not WorkGuard. |
| **Unknown — not yet tested** | No verified control is in place. This channel is a residual risk. Do not claim it is blocked. |
| **Out of scope — accepted risk** | The company has acknowledged and accepted this channel as an uncontrolled residual risk for the current phase. Document the acceptance decision and review date. |

---

## 3. Channel coverage matrix

### 3.1 Removable storage

| Channel | Mechanism | Status | Covered OS editions | Notes / Limitations |
|---|---|---|---|---|
| USB mass storage (read) | Windows device-control policy via Group Policy or Microsoft Defender for Endpoint Device Control | **Unknown — not yet tested** | TBD — requires Windows edition matrix (see ENDPOINT_AGENT.md §5) | Read control varies by mechanism; test separately from write control |
| USB mass storage (write) | Same as above | **Unknown — not yet tested** | TBD | Primary MVP target; must confirm which Windows editions support the selected mechanism without additional licensing |
| USB MTP (e.g., Android phone) | MDE Device Control or Group Policy | **Unknown — not yet tested** | TBD | MTP uses a different device class than USB MSC; must be tested separately |
| USB CD/DVD (optical) | Windows device-control policy | **Unknown — not yet tested** | TBD | Less common; include if optical drives exist in the fleet |
| SD card reader (internal or USB) | Windows device-control policy | **Unknown — not yet tested** | TBD | May require separate device class entry |
| FireWire / Thunderbolt storage | Windows device-control policy | **Unknown — not yet tested** | TBD | Thunderbolt 3/4 may require additional policy; verify |

### 3.2 Browser uploads

> All browser upload tests must record: browser name, browser version, browser profile type
> (work profile vs. personal profile vs. incognito), DLP provider name and version, OS build.

| Channel | Mechanism | Status | Covered browsers/OS | Notes / Limitations |
|---|---|---|---|---|
| Chrome upload to blocked cloud destination | Endpoint DLP provider (vendor TBD — see §6) | **Unknown — not yet tested** | TBD | Requires DLP vendor selection in Phase 4 |
| Edge upload to blocked cloud destination | Endpoint DLP provider | **Unknown — not yet tested** | TBD | Edge may have native DLP integration via Microsoft Purview |
| Firefox upload to blocked cloud destination | Endpoint DLP provider | **Unknown — not yet tested** | TBD | Many DLP products have limited Firefox support; verify explicitly |
| Chrome incognito / personal profile | Endpoint DLP provider | **Unknown — not yet tested** | TBD | Many endpoint DLP products cannot inspect incognito traffic without certificate pinning bypass; high-risk gap |
| Edge InPrivate / personal profile | Endpoint DLP provider | **Unknown — not yet tested** | TBD | Same concern as Chrome incognito |
| Browser download then re-upload from non-monitored app | Endpoint DLP + application control | **Unknown — not yet tested** | TBD | Multi-step exfiltration; DLP file-classification rules must cover downloaded artifacts |

### 3.3 Desktop cloud sync clients

| Channel | Mechanism | Status | Covered apps | Notes / Limitations |
|---|---|---|---|---|
| OneDrive personal sync | Endpoint DLP / network block / application control | **Unknown — not yet tested** | TBD | OneDrive for Business may be allowed; personal must be distinguished |
| Dropbox desktop client | Endpoint DLP / network block / application control block | **Unknown — not yet tested** | TBD | Application control (block/restrict Dropbox) is the most reliable option |
| Google Drive for Desktop | Endpoint DLP / network block / application control block | **Unknown — not yet tested** | TBD | Similar to Dropbox |
| iCloud Drive for Windows | Endpoint DLP / application control | **Unknown — not yet tested** | TBD | Less common on corporate fleets; include if relevant |
| Box Drive | Endpoint DLP / application control | **Unknown — not yet tested** | TBD | |

### 3.4 Email

| Channel | Mechanism | Status | Covered apps | Notes / Limitations |
|---|---|---|---|---|
| Personal Gmail via browser | Endpoint DLP (covers HTTP/S upload path) | **Unknown — not yet tested** | TBD | Same as browser upload; DLP must classify attachment |
| Personal Outlook.com / Hotmail via browser | Endpoint DLP | **Unknown — not yet tested** | TBD | |
| Outlook desktop client to approved corporate address | Allowed — legitimate workflow | N/A | Microsoft Outlook | Corporate email is a permitted channel; content policies are separate |
| Outlook desktop client to personal/external address | Endpoint DLP | **Unknown — not yet tested** | TBD | DLP must intercept SMTP/MAPI; confirm provider support |
| Third-party desktop email client (Thunderbird, etc.) | Endpoint DLP or application control | **Unknown — not yet tested** | TBD | Application control block is more reliable than DLP interception for non-standard clients |

### 3.5 Git and source control

| Channel | Mechanism | Status | Notes / Limitations |
|---|---|---|---|
| Git push over HTTPS to approved corporate host | Allowed — legitimate workflow | Repository credential controls, branch protection, and audit logs on the approved Git host are the enforcement mechanism; WorkGuard can revoke access on offboarding |
| Git push over SSH to approved corporate host | Allowed — legitimate workflow | Same |
| Git push over HTTPS to personal GitHub / GitLab / Bitbucket | Network control / DLP (HTTPS inspection) | **Unknown — not yet tested** | HTTPS inspection may be blocked by certificate pinning in newer Git clients; test explicitly |
| Git push over SSH to personal host | Network firewall / SSH egress control | **Unknown — not yet tested** | SSH on port 22 can be blocked at network level; Git over SSH on port 443 is harder to distinguish from HTTPS; test explicitly |
| Git over alternative ports or custom servers | Network egress control | **Unknown — not yet tested** | Hard to enumerate; document as residual risk |
| Local Git clone to removable media | USB control (see §3.1) | Inherits USB coverage | Covered only if USB write is blocked |

### 3.6 Messaging and collaboration

| Channel | Mechanism | Status | Notes / Limitations |
|---|---|---|---|
| Approved corporate chat (e.g., Slack corporate workspace, Teams) | Allowed — legitimate workflow | Data-loss controls on the approved platform; WorkGuard does not intercept |
| Personal Slack workspace file upload | Endpoint DLP / network control | **Unknown — not yet tested** | |
| WhatsApp Web file send | Endpoint DLP (browser path) | **Unknown — not yet tested** | |
| Telegram Desktop file send | Application control / DLP | **Unknown — not yet tested** | |
| Discord file upload | Endpoint DLP / application control | **Unknown — not yet tested** | |

### 3.7 Network file transfer

| Channel | Mechanism | Status | Notes / Limitations |
|---|---|---|---|
| SMB share to approved corporate file server | Allowed — legitimate workflow | Access controlled on the file server |
| SMB share to personal NAS or external share | Network firewall / SMB egress block | **Unknown — not yet tested** | Blocking outbound SMB (port 445) at the firewall is effective; test that the agent can apply and verify this rule |
| FTP / SFTP upload to external server | Network firewall | **Unknown — not yet tested** | Block outbound FTP (21) and SFTP (22) to non-approved destinations |
| SCP / rsync over SSH | Network firewall / SSH egress | **Unknown — not yet tested** | Same as SSH Git push |
| WebDAV over HTTPS | Endpoint DLP (HTTPS inspection path) | **Unknown — not yet tested** | |

### 3.8 Wireless and proximity channels

| Channel | Mechanism | Status | Notes / Limitations |
|---|---|---|---|
| Bluetooth file transfer (OBEX) | Windows Bluetooth policy / device-control | **Unknown — not yet tested** | Windows can disable Bluetooth via device-control policy; test specifically for OBEX file transfer |
| Windows Nearby Sharing | Windows Group Policy (`DisableNearbySharing`) | **Unknown — not yet tested** | Verify the policy key and supported editions |
| AirDrop equivalent (third-party) | Application control | **Unknown — not yet tested** | |
| Wi-Fi Direct / mobile hotspot tethering | Network policy / Group Policy | **Unknown — not yet tested** | An employee could tether a phone and use a personal data connection, bypassing corporate network controls; document as residual risk |

### 3.9 Printing and screen capture

| Channel | Mechanism | Status | Notes / Limitations |
|---|---|---|---|
| Physical printing to a local or network printer | Endpoint DLP (print interception — not all providers support this) | **Unknown — not yet tested** | Print DLP coverage varies significantly by provider; verify before claiming |
| Print to PDF / XPS / Microsoft Print to PDF | Endpoint DLP (virtual print path) | **Unknown — not yet tested** | Resulting file is local; combine with file-egress controls |
| Screen capture (Win + PrtScn, Snipping Tool) | **Out of scope — accepted risk** | Cannot be reliably prevented by user-mode software; watermarking where supported is a detective, not preventive, control |
| Screen photography by personal phone | **Out of scope — accepted risk** | Cannot be prevented technically; procedural and physical controls only |
| Screen recording software | Application control (block unsigned or unapproved screen-capture tools) | **Unknown — not yet tested** | Application control can block specific tools; cannot block all possible tools |

### 3.10 Remote access

| Channel | Mechanism | Status | Notes / Limitations |
|---|---|---|---|
| Approved corporate VPN | Allowed — legitimate workflow | Traffic routes through corporate network controls |
| Personal VPN client (e.g., NordVPN, ExpressVPN) | Application control / network policy | **Unknown — not yet tested** | A personal VPN can bypass DNS-based and URL-based DLP; application control to block known VPN clients is the most effective mitigation, but cannot enumerate all VPN tools |
| Remote desktop to external machine (RDP) | Network firewall / DLP | **Unknown — not yet tested** | Outbound RDP (port 3389) can be blocked; copy-paste via RDP clipboard is an exfiltration path |
| TeamViewer / AnyDesk / similar | Application control / network egress | **Unknown — not yet tested** | Remote control tools enable real-time screen viewing and file transfer by a remote party |

---

## 4. Approved destination allowlist (to be defined in Phase 4)

Before enforcing DLP policies, define and document the list of approved destinations so that
legitimate workflows are not disrupted. At minimum, include:

- Approved corporate Git host (hostname or IP range)
- Approved corporate cloud storage
- Approved package registries (npm, PyPI, Maven, NuGet) — read-only
- Corporate email domain(s)
- Approved CI/CD service endpoints
- Approved video-conferencing services

---

## 5. Exception process

Any channel blocked by policy can be opened for a specific device, user, or time window
through the exception workflow defined in `DESIGN.md §Exceptions`. Every exception requires:
a named approver, a business justification, a defined expiry, and a compensating control or
monitoring commitment. No permanent exceptions without a formal risk acceptance.

---

## 6. DLP vendor evaluation (Phase 4 decision)

A DLP vendor must be selected before Phase 4 begins. Key evaluation criteria:

| Criterion | Notes |
|---|---|
| Browser coverage | Must document which browsers and versions are supported; Chrome and Edge are minimum |
| Application coverage | Document which desktop apps (email clients, sync clients) are inspected |
| Windows edition requirements | Document minimum Windows edition and any Intune/MDE dependency |
| Protocol coverage | HTTP/S, SMTP, SMB, FTP, SSH — document each explicitly |
| Incognito / private browsing | Can the provider inspect private browsing sessions? Document the method |
| Audit trail | Does the provider emit machine-readable events consumable by WorkGuard? |
| Licensing model | Per-device, per-user, or bundled with an existing Microsoft/security product? |

Candidate products to evaluate: Microsoft Purview Information Protection (if Microsoft 365
licensing permits), Forcepoint DLP, Symantec DLP, Zscaler, or a secure web gateway with TLS
inspection. Evaluate based on actual fleet OS editions and existing licensing before committing.

---

## 7. Review and maintenance

- **After each major OS update:** Re-test at least USB, app-control, and DLP browser rows.
- **After each DLP provider update:** Re-test the rows the provider covers.
- **Quarterly:** Review all "Unknown" rows; escalate unresolved critical gaps to management.
- **Before adding an employee to the pilot:** Confirm their device configuration is covered
  by at least the rows marked "Blocked — verified."

All test results must record: date, OS build, application name and version, DLP provider name
and version, policy version, pass/fail result, and the specific limitation if partial.
