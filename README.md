# WorkGuard — Secure Local Development Management

> **Status:** Architecture/documentation starter pack. This repository is not a working endpoint-security product and must not be represented as one.

WorkGuard is a proposed system for managing security policies on company-managed Windows laptops while source code and day-to-day work files remain local to those laptops. It combines a central administration/control plane with a Windows endpoint agent that reports device health and coordinates supported Windows security controls.

## Primary goals

- Keep working copies of source code and files on company-managed laptops.
- Restrict removable storage and unapproved applications using supported Windows controls.
- Centralize device inventory, policy assignments, policy status, security alerts, and administrative audit records.
- Reduce unauthorized uploads and external sharing through an **explicitly integrated, supported endpoint DLP/browser/network control**. The WorkGuard agent alone cannot reliably intercept all uploads from all applications.
- Use private, permission-controlled source-code hosting when team collaboration and off-device backup are required.
- Fail safely when a device is unknown, a policy is invalid, or policy enforcement cannot be verified.

## Non-goals and boundaries

- Guaranteeing that source code cannot ever be copied, photographed, manually reproduced, or disclosed.
- Building a custom kernel driver, antivirus engine, cryptographic library, VPN, identity provider, video-conferencing stack, or Git implementation.
- Monitoring employees secretly. Device telemetry must be documented, proportionate, access-controlled, and disclosed through company policy and applicable law.
- Claiming a security control is enforced merely because the dashboard contains a setting. Enforcement must be verified on the endpoint.

## Recommended initial scope

1. Windows 11 company-managed devices only; define supported Windows editions after validating policy availability.
2. Central administrator portal and API for device inventory, policy assignment, event collection, and audit history.
3. A signed Windows service that identifies the device, retrieves authenticated policy, invokes supported Windows configuration mechanisms, and reports verifiable status.
4. USB-storage policy based on native Windows policy or Microsoft Defender for Endpoint Device Control, depending on licensing and requirements.
5. Application control via App Control for Business or AppLocker after audit-mode testing.
6. Integration interface for endpoint DLP and managed browser/network controls; do not implement upload interception by filesystem watching alone.
7. A pilot with test data before real source code is covered.

## Documentation map

- [ARCHITECTURE.md](ARCHITECTURE.md) — system architecture, sequence diagrams, and trust boundaries
- [SECURITY.md](SECURITY.md) — security requirements, hardening rules, and threat mitigations
- [SIGNING_SPEC.md](SIGNING_SPEC.md) — normative specification for Ed25519 policy signing and RFC 8785 canonical encoding
- [CHANNEL_COVERAGE.md](CHANNEL_COVERAGE.md) — comprehensive DLP exfiltration channel matrix and verified control status
- [EMPLOYEE_NOTICE.md](EMPLOYEE_NOTICE.md) — template employee privacy, telemetry, and monitoring disclosure notice
- [DESIGN.md](DESIGN.md) — product UX, policy states, freshness indicators, and user flows
- [API.md](API.md) — API contract, rollback semantics, and security rules
- [openapi.yaml](openapi.yaml) — machine-readable OpenAPI 3.1 specification for control and agent routes
- [DATA_MODEL.md](DATA_MODEL.md) — database entities, relations, and data retention policies
- [ENDPOINT_AGENT.md](ENDPOINT_AGENT.md) — Windows service design, PKI, edition support matrix, and DACL hardening
- [DEPLOYMENT.md](DEPLOYMENT.md) — cloud deployment, runtime versions, cost estimates, and immutable SIEM sinks
- [OPERATIONS.md](OPERATIONS.md) — incident response, operational runbooks, and stale-device visibility rules
- [THREAT_MODEL.md](THREAT_MODEL.md) — threat scenarios, attack trees, and mitigations
- [TESTING.md](TESTING.md) — security test suites and release verification gates
- [ROADMAP.md](ROADMAP.md) — staged implementation plan and phase exit criteria
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution rules, PR checklist, and telemetry change governance
- [schemas/policy.schema.json](schemas/policy.schema.json) — strictly typed policy schema with per-control settings validation

## High-level layout

```text
workguard/
├── admin-web/             # React + TypeScript administrator portal
├── control-api/           # FastAPI control plane
├── endpoint-agent/        # C#/.NET Windows service and installer
├── integrations/          # adapters to supported Windows/security products
├── schemas/               # versioned policy/event contracts
├── infra/                 # IaC, deployment templates, dashboards, alerts
├── tests/                 # API, policy, Windows integration, security tests
├── ARCHITECTURE.md
├── SECURITY.md
├── DESIGN.md
├── API.md
└── ...
```

## Mandatory implementation rule

WorkGuard may **orchestrate supported platform controls**; it must not pretend that a normal user-mode service can provide complete DLP enforcement across every process, browser, protocol, and network path. For file-upload blocking, evaluate and integrate a supported endpoint DLP or secure web gateway product and document the exact channels, applications, browsers, file types, and operating-system editions covered.

## Authoritative references

- [Windows application control overview](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/)
- [Application Control for Windows](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/)
- [Microsoft Defender for Endpoint device control](https://learn.microsoft.com/en-us/defender-endpoint/device-control-overview)
- [Microsoft Defender removable-storage access control](https://learn.microsoft.com/en-us/defender-endpoint/device-control-removable-storage-access-control)
- [Windows driver security checklist](https://learn.microsoft.com/en-us/windows-hardware/drivers/driversecurity/driver-security-checklist)

Re-check edition, licensing, policy and browser support at implementation time because these vary by product and can change.
