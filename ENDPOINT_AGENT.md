# WorkGuard Windows Endpoint Agent

> **Implementation status:** This document describes the proposed production
> Windows service. That service is **not implemented** in this repository.
> The only executable endpoint component is
> [`endpoint-agent/simulator.py`](endpoint-agent/simulator.py), a development
> harness that performs real envelope verification and reports simulated
> read-back results. The harness authenticates with a per-device bearer token;
> mTLS, certificate storage, MSI packaging, provider adapters, and actual
> Windows enforcement described below remain future work.

## 1. Responsibility

The agent coordinates policy delivery and status reporting. It is not an antivirus, universal upload interceptor, kernel driver, or substitute for operating-system security controls and endpoint DLP.

## 2. Proposed implementation

- Language/runtime: C#/.NET 8 LTS Windows service. Pin to a named LTS release; update to .NET 10 LTS when released and tested.
- Installer: signed MSI or equivalent managed deployment package (code-signing certificate: OV or EV authenticode certificate from a Microsoft-trusted CA; EV preferred for SmartScreen reputation).
- Transport: mTLS using a device-bound client certificate (see §9 for PKI details).
- Local state: minimal versioned state under an ACL-protected `%ProgramData%\WorkGuard` directory; secrets in Windows CNG certificate store or TPM-backed key storage, not plain JSON.
- Logging: Windows Event Log (source `WorkGuardAgent`) plus bounded local diagnostic logs under `%ProgramData%\WorkGuard\Logs`; do not log source files, tokens or personal file contents.
- Update: signed manifest and signed package; verify signer/digest, enforce anti-rollback, stage update and recover from interruption.

## 3. Service lifecycle

1. Start and validate configuration.
2. Load device credential from Windows certificate store (see §9).
3. Verify agent binary/configuration integrity as supported; report agent version.
4. Establish authenticated connection to control plane using mTLS device certificate.
5. Send heartbeat and request assigned signed policy.
6. Validate policy signature, schema, target device, issue/expiry and monotonic version (see `SIGNING_SPEC.md`).
7. Compare desired state with observed OS/provider state.
8. Apply changes through the selected supported provider adapter.
9. Read back state; report per-control result.
10. Queue bounded metadata events while offline and retry with backoff; never queue source file contents.

## 4. Policy interface

Each control adapter implements a contract equivalent to:

```text
Validate(policy) -> validation result
Plan(policy, currentState) -> proposed changes
Apply(plan) -> apply result
Verify(policy, currentState) -> observed control result
Rollback(previousPolicy) -> rollback result (where supported)
```

Do not implement an arbitrary remote-command engine. Policies must map to a finite set of typed controls with validated values. Never send shell commands or PowerShell scripts from the admin UI to run with SYSTEM privileges.

### Control result `safe_details` field

The `safe_details` field in a control result is intended for non-sensitive diagnostic information only. Permitted content:

- Windows registry key names (not values): e.g., `HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices`
- Windows policy GUID strings
- Numeric error codes: e.g., `0x80070005`
- Vendor-documented state identifiers: e.g., `MDE_DEVICE_CONTROL_POLICY_APPLIED`

**Prohibited content in `safe_details`:** file paths, file contents, user names, email addresses, security tokens, registry values, process command lines, or any data that could identify an individual or expose sensitive configuration. The server-side API validates `safe_details` against an allowlist pattern before storage. Payloads matching token patterns, email addresses, or file path patterns (e.g., `C:\Users\`) are rejected with a 400 error.

## 5. Initial adapters and Windows platform support matrix

Before implementing any control adapter, confirm the selected control mechanism is available on the actual Windows editions in the fleet. The table below reflects requirements as of October 2026; **verify against current Microsoft documentation at implementation time** as edition requirements can change.

### Platform support matrix

| Control | Mechanism | Minimum Windows edition | Additional licensing required | Fallback if unavailable |
|---|---|---|---|---|
| USB mass storage block | **Microsoft Defender for Endpoint (MDE) Device Control** | Windows 10 1809+ (any edition) | MDE Plan 1 or Plan 2 (see note 1) | Group Policy removable storage access rules (available on Pro+; less granular) |
| USB mass storage block (no MDE) | Group Policy: `HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices` | Windows 10/11 Pro, Enterprise, Education | None (included in Windows) | Not available on Home |
| Application control | **App Control for Business (WDAC)** | Windows 10/11 Pro, Enterprise, Education (not Home) | None (included in Windows) | AppLocker (Enterprise/Education only — see note 2) |
| Application control (legacy) | **AppLocker** | Windows 10/11 Enterprise, Education only | None | App Control for Business (preferred) |
| Disk encryption status query | BitLocker WMI provider (`Win32_EncryptableVolume`) | Windows 10/11 Pro, Enterprise, Education | None (BitLocker on Pro+; Device Encryption on Home) | Report `unknown` if WMI query fails |
| Endpoint protection status query | Windows Security Center WMI / Security Center COM API | All editions | None | Report `unknown` if query fails |
| DLP provider status | Vendor-specific integration (see CHANNEL_COVERAGE.md §6) | Varies by DLP vendor | DLP product license | Report `not_configured` if provider is absent |
| Network/firewall policy | Windows Firewall via `netsh advfirewall` / WMI | All editions | None | |
| Bluetooth control | Group Policy: `Computer Configuration > Windows Settings > Security Settings > System Services > Bluetooth Support Service` | Pro, Enterprise, Education | None | |

> **Note 1 — MDE licensing:** MDE Device Control is included in MDE Plan 1 (~$15/device/month as of 2026; verify current pricing) or MDE Plan 2 (~$15/device/month, superset features). It is also bundled in Microsoft 365 Business Premium. Evaluate existing Microsoft licensing before purchasing separately.
>
> **Note 2 — AppLocker vs. App Control for Business:** App Control for Business (formerly WDAC) is the strategic replacement for AppLocker. New deployments should prefer App Control for Business. AppLocker is available on Enterprise/Education SKUs only; App Control for Business works on Pro and above.
>
> **Home edition:** Windows 10/11 Home is explicitly out of scope for the WorkGuard MVP. Group Policy and most security APIs are not available on Home. Company-managed devices must run a Pro or higher edition.

### Removable storage adapter

- Choose between MDE Device Control (recommended, requires MDE license) or native Group Policy (no additional license, less granular event data).
- Document the exact device classes covered: USB Mass Storage, MTP, CD/DVD, SD card readers. These are separate classes and must be tested separately.
- Verify the effective policy and test allow/deny behavior with harmless USB media on each supported OS build.
- Handle legitimate exceptions through a time-limited allow policy approved by IT/security, recorded as an exception in the management system.

### Application control adapter

- Build and test policy in audit mode first; review the Windows Event Log Application and Services Logs > Microsoft > Windows > CodeIntegrity for blocked applications.
- Review developer tool compatibility: compilers, build systems, test runners, package managers, editors. Add any legitimate tools to the allowlist before enforcement.
- Move to enforcement only after a test cohort passes, rollback procedure is tested, and IT support is ready to handle exception requests.
- Use App Control for Business or AppLocker as appropriate to the supported fleet; do not use a simplistic process-name blocklist.

### Disk encryption and endpoint protection

- Query and report supported provider status; do not implement home-grown disk encryption or antivirus.
- If status cannot be verified, report `unknown` rather than `enabled`.

### Upload/DLP provider

- Use an adapter to integrate a supported DLP or secure web gateway provider (see `CHANNEL_COVERAGE.md`).
- Display provider name, version, platform/browser coverage, and most recent successful synchronization.
- WorkGuard must not report universal upload prevention. Channel coverage is defined by the provider and verified tests.

## 6. Service hardening

### Windows service security descriptor (DACL)

The WorkGuard Windows service must be registered with a restrictive Security Descriptor. Use the following SDDL string as a baseline; adjust for your specific service name and review with a Windows security specialist before deployment:

```
D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)
```

This grants:
- `SY` (LocalSystem): full control
- `BA` (Builtin Administrators): full control
- `IU` (Interactive Users): only `SERVICE_QUERY_STATUS`, `SERVICE_QUERY_CONFIG`, `SERVICE_ENUMERATE_DEPENDENTS`, `SERVICE_INTERROGATE`, `READ_CONTROL` — **cannot stop, start, or configure the service**
- `SU` (Service logon users): same as IU

Apply this descriptor using `sc.exe sdset WorkGuardAgent "<sddl>"` during installation. Verify it by running `sc.exe sdshow WorkGuardAgent` and testing that a standard user account receives `Access is denied` when running `sc stop WorkGuardAgent`.

**Important limitation:** This DACL prevents standard user accounts from stopping or reconfiguring the service through the Service Control Manager. However, a user with local administrator privileges can modify or remove this DACL and then stop the service. This is an inherent Windows limitation for user-mode services. Mitigations:

1. **Standard user for daily work:** Company policy must require employees to use standard (non-administrator) accounts for day-to-day development. Separate administrator credentials for IT-authorized operations only.
2. **Heartbeat-based tamper detection:** If the agent stops unexpectedly, the control plane will detect a missed heartbeat within the stale threshold and mark the device noncompliant. Restrict sensitive repository access on devices that become stale or noncompliant.
3. **Protected Process Light (PPL):** PPL can be applied to Windows services to prevent code injection from non-PPL processes. Evaluate PPL for the WorkGuard service in Phase 2. PPL requires the service to be registered with a specific launch protection flag and limits the service's own capabilities; test thoroughly before enabling.

### Other hardening requirements

- Use ACLs for directories (`%ProgramData%\WorkGuard`), named pipes, registry keys under `HKLM\SOFTWARE\WorkGuard`, and update download locations. The directory ACL must deny write access to non-administrator users.
- Validate local IPC input and authenticate caller identity using named pipe ACLs.
- Do not listen on a network port unless it is essential; if required, authenticate and restrict it.
- Do not collect keystrokes, clipboard contents, screen capture, webcam/microphone data, or file contents.
- Test tampering, unexpected shutdown, disk-full conditions, expired policy, expired device credential, invalid signatures, and offline operation.

## 7. Offline behavior

- Keep currently applied native security controls active while offline.
- Use last-known-good policy only while within its validity window (see `SIGNING_SPEC.md` §6 — the agent rejects an expired policy).
- Do not relax enforcement merely because the control plane is unavailable.
- Report stale device state when reconnection occurs.
- Do not claim central visibility while offline; dashboard must show last-seen time.

## 8. Driver policy

Do not create a kernel-mode driver in the MVP. If future analysis concludes a driver is necessary, the team must conduct specialist review, threat modeling, driver verification and applicable signing/qualification work. Kernel code can compromise the entire OS and is not an appropriate shortcut for blocking file transfers.

## 9. Device identity and PKI

This section defines the device credential system — the root of trust for all agent-to-API communication.

### Certificate authority

Use a **Private Certificate Authority (CA)** operated by WorkGuard or a managed CA service:

- **Recommended for Phase 2 pilot:** Self-managed CA using .NET `CertificateRequest` / OpenSSL for the pilot, with a root CA certificate distributed to enrolled devices. This avoids third-party dependencies during initial development but must be replaced with a managed CA for production.
- **Recommended for production:** AWS Private CA, Azure Private CA (part of Azure Key Vault), or an SCEP/EST-compatible managed CA that integrates with the enrollment flow. These provide audit trails, automatic revocation, and managed key storage.
- **Not recommended:** A single long-lived self-signed certificate shared across all devices. Each device must have its own unique certificate.

### Enrollment and certificate issuance flow

1. Administrator creates an enrollment code via `POST /admin/enrollment-codes`.
2. The installer delivers the enrollment code to the device (QR code, secure link, or provisioning script).
3. On first run, the agent:
   a. Generates an Ed25519 or RSA 2048+ key pair in the **Windows CNG** key store, backed by the TPM if available (`CngKey.Create` with `CngKeyCreationOptions.MachineKey` and `NCRYPT_TPM_PAD_PSS_IGNORE_SALT_LENGTH` for TPM-backed keys).
   b. Constructs a Certificate Signing Request (CSR) containing the device's public key and a Subject Alternative Name (SAN) with the enrollment code as a claim.
   c. Calls `POST /agent/enroll` with the enrollment code, CSR (DER/PEM), agent version, and OS version.
4. The API validates the enrollment code (single-use, not expired), creates a device record, submits the CSR to the CA, and returns a `credential_enrollment_uri` pointing to the issued certificate.
5. The agent fetches the certificate from `credential_enrollment_uri`, installs it in the Windows certificate store under `LocalMachine\My`, and deletes the enrollment code from local storage.
6. All subsequent API calls use mTLS: the agent presents this certificate as the client certificate; the server validates the certificate chain, checks the device record in the database, and confirms the device is not revoked.

### Private key storage

| Option | When to use | Notes |
|---|---|---|
| TPM-backed CNG key (`NCRYPT_MACHINE_KEY` + TPM provider) | Preferred — use when a TPM 2.0 chip is present | Key cannot be exported; survives OS re-install only if TPM is preserved |
| CNG Software key store (`MS_KEY_STORAGE_PROVIDER`) | Fallback when no TPM | Exportable in theory; protect the key store with DACL; log if TPM is absent |
| DPAPI-protected file | Not recommended for new deployments | Use only as a last resort; prefer CNG |

At enrollment, the agent must detect whether a TPM 2.0 is available, log the key storage method used, and report it to the control plane as part of the device metadata.

### Certificate lifetime and renewal

- Issue device certificates with a **90-day validity period** for the pilot; adjust to 12 months for production after the renewal flow is validated.
- The agent must begin the renewal process when the certificate has 20% of its lifetime remaining (e.g., 18 days before expiry for a 90-day cert).
- Renewal: the agent generates a new key pair and CSR, presents the existing client certificate to authenticate to a dedicated `POST /agent/renew-credential` endpoint (to be added to the API in Phase 2), and the server issues a new certificate. The old certificate remains valid until expiry or explicit revocation.

### Revocation

- The server sets `revoked_at` on the `device_credentials` record and stores the certificate thumbprint.
- On each API request, the server checks whether the presented client certificate thumbprint is in the revoked set; if so, it returns 401.
- Certificate Revocation Lists (CRL) or OCSP: publish a CRL for the CA and configure the Windows SCHANNEL to check CRL on client-certificate validation. For the pilot, manual CRL publishing after revocation is acceptable; automate for production.

### Server-side certificate validation

The API must:

1. Require a client certificate on all `/agent/*` endpoints (reject with 401 if absent).
2. Validate the certificate chain up to the WorkGuard private CA root.
3. Check the certificate serial number or thumbprint against the `device_credentials` table.
4. Confirm `revoked_at IS NULL` for the matched record.
5. Extract the device ID from the `device_credentials.device_id` foreign key; use this as the authoritative device identity for the request. Do not trust a device ID supplied in the request body.
