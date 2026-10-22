# WorkGuard Employee Privacy and Monitoring Notice

> **Template status:** This is a template requiring review and approval by HR and legal
> counsel before distribution. Replace all `[COMPANY NAME]`, `[CONTACT]`, and
> `[JURISDICTION]` placeholders with company-specific information. Do not enroll any
> employee device before the final, approved version of this notice has been delivered to
> that employee and a receipt has been recorded.
>
> **This is not legal advice.** Requirements vary by jurisdiction (e.g., GDPR Article 13
> in the EU/UK, state privacy laws in the US, local labour law). Obtain qualified legal
> review before deployment.

---

## Notice to Employees: WorkGuard Device Monitoring

**[COMPANY NAME]** operates a security management system called **WorkGuard** on
company-managed Windows laptops. This notice explains what data WorkGuard collects, why,
who can access it, how long it is kept, and your rights. Please read it before your device
is enrolled.

If you have questions, contact **[CONTACT — e.g., security@company.com or your HR representative]**.

---

### 1. Why WorkGuard is deployed

[COMPANY NAME] stores source code and sensitive work files on company-managed laptops. To
reduce the risk of accidental or unauthorized disclosure, WorkGuard:

- Enforces security policies (for example, blocking unauthorized USB storage and unapproved
  application execution) on company devices.
- Reports the status of those security controls to a central management system.
- Collects security-relevant events (for example, a blocked USB write attempt) so that the
  company can detect and respond to potential data incidents.

WorkGuard is **not** a general productivity monitoring tool. It does not track websites you
visit for personal reasons, record keystrokes, capture screenshots, read your email, or
monitor your personal files.

---

### 2. What data WorkGuard collects

WorkGuard collects the following categories of data from your company-managed laptop.

#### 2a. Device identity and health metadata

| Data item | Example | Why collected |
|---|---|---|
| Device identifier (UUID assigned at enrollment) | `a1b2c3d4-...` | Identifies the device in the management system |
| Operating system version and edition | `Windows 11 Pro 24H2 Build 26100` | Determines which security controls are available |
| Agent software version | `1.2.3` | Ensures the security software is up to date |
| Last contact time | `2026-10-22 10:00 UTC` | Detects devices that have lost contact with the management system |
| Disk encryption status | `BitLocker: active` | Required compliance check |
| Endpoint protection status | `Defender: active, up to date` | Required compliance check |

#### 2b. Policy and control status

| Data item | Example | Why collected |
|---|---|---|
| Assigned security policy version | `12` | Confirms the device has received the current policy |
| Control status per policy requirement | `USB storage: enforced`, `App control: audit` | Confirms each security control is active; identifies failures |
| Control failure codes | `USB_POLICY_NOT_SUPPORTED` | Helps IT diagnose configuration problems |

#### 2c. Security events (when applicable)

WorkGuard reports security-relevant events. Examples:

- A USB storage device was connected and blocked by policy.
- An application attempted to run and was blocked by the application-control policy.
- The WorkGuard agent was stopped unexpectedly.
- The device has not contacted the management server beyond the expected interval.

Events include: event type, timestamp, device identifier, process name or signer (where
required to understand the event), and any destination domain relevant to a network control
event. Events do **not** include source-code contents, file bodies, keystrokes, clipboard
contents, screenshots, or your personal browsing history.

#### 2d. What WorkGuard does NOT collect

- Source-code content, file bodies, or document text.
- Keystrokes or typing patterns.
- Screenshots or screen recordings.
- Clipboard contents.
- Audio, video, or microphone data.
- Personal browsing history unrelated to a security-policy event.
- Personal files stored outside company-designated directories.

Any expansion of the data categories above requires a documented policy change, a revised
notice delivered to affected employees, and — where legally required — employee or works
council consultation before deployment.

---

### 3. Who can access this data

| Role | What they can see |
|---|---|
| Security administrator | All device health, policy status, and security events for devices in their assigned organization. Access is logged and audited. |
| IT operator | Device health and control status; cannot see security event details without elevated access. |
| Auditor | Read-only access to security events and administrator audit records. |
| Other employees | Cannot see any other employee's device data. |

Your WorkGuard agent display on your own device shows your device's current health and
policy status. It does not show other employees' data.

Access to security data is itself audited: administrators cannot review your security events
without leaving a record of that access.

---

### 4. How long data is retained

| Category | Retention period |
|---|---|
| Current device health status | Maintained while the device is enrolled; deleted on device revocation |
| Historical status changes | Up to 90 days |
| Security events | 90–180 days (subject to company policy and legal requirements in **[JURISDICTION]**) |
| Administrator and policy audit records | 180–365 days or the company-approved period |
| Enrollment codes | Deleted immediately on use or expiry; only a cryptographic hash is stored while valid |

Retention periods may be extended if required by an active legal hold or investigation.
Data is not retained after the applicable period without a documented justification.

---

### 5. Legal basis for processing (EU/UK employees — GDPR)

> **[Jurisdiction-specific section — complete with legal review for each jurisdiction where
> employees are located.]**

For employees in the EU or UK, the legal basis for processing the data described in §2 is
**legitimate interest** (Article 6(1)(f) GDPR): [COMPANY NAME]'s legitimate interest in
protecting its intellectual property and confidential information, balanced against your
rights and freedoms as a data subject.

A Legitimate Interests Assessment (LIA) has been / will be completed before device
enrollment begins. A copy is available from **[CONTACT]** on request.

---

### 6. Your rights

Depending on your jurisdiction, you may have the right to:

- **Access** the personal data WorkGuard holds about your device.
- **Correct** inaccurate data.
- **Restrict or object** to processing in certain circumstances.
- **Request deletion** of data when it is no longer necessary for the purposes described above.

To exercise any of these rights, contact **[CONTACT]**. We will respond within the
timeframe required by applicable law.

---

### 7. Use in disciplinary or legal proceedings

Security event data may be used as evidence in an investigation or disciplinary process
where there is reasonable suspicion of a policy violation or unauthorized data disclosure.
Any such use will follow [COMPANY NAME]'s HR and disciplinary procedures and applicable law.

Data will not be used for the purposes of general performance monitoring or routine
productivity assessment.

---

### 8. Changes to this notice

[COMPANY NAME] will notify you of any material change to the data collected, purposes, or
retention before the change takes effect. The current version of this notice is always
available at **[INTERNAL LINK OR LOCATION]**.

---

### 9. Questions and complaints

For questions about this notice or how your data is handled:

- **Internal contact:** **[CONTACT — e.g., Data Protection Officer or HR]**
- **Email:** **[security@company.com or dpo@company.com]**

If you believe your data has been mishandled, you have the right to lodge a complaint with
the relevant data protection authority in your jurisdiction (for example, the ICO in the UK
or your national supervisory authority in the EU).

---

*Version:* Draft — requires legal and HR review before distribution  
*Prepared:* 2026-10-22  
*Next review:* Before any device enrollment; and annually thereafter
