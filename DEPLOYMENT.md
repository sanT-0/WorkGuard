# WorkGuard Deployment Guide

## 1. Initial environment

For a small team, prefer managed cloud services over operating your own internet-facing server. The laptops store code locally; the cloud control plane stores device/policy metadata and audit records only.

Environments:
- `local`: developer machines, fake devices and test keys only.
- `staging`: isolated test tenant and test laptops; no production source code or credentials.
- `production`: separate identity application, database, keys, domain, logs, backups and operator roles.

Never reuse development signing keys, certificates, enrollment codes or secrets in production.

## 2. Minimum services and runtime versions

### Runtime Versions (F-022)
- **Backend Control Plane:** Python 3.12+ (FastAPI, Pydantic v2; managed via `uv` or `poetry`)
- **Dashboard Frontend:** Node.js 20 LTS (React 18+, TypeScript 5+, built with Vite)
- **Windows Endpoint Agent:** .NET 8 LTS (C# 12, Microsoft.Extensions.Hosting Windows Service)
- **Database:** PostgreSQL 16+ (with pgcrypto extension enabled)

### Required Infrastructure Services
- FastAPI API service behind a managed TLS ingress/reverse proxy.
- Managed PostgreSQL with private networking where available, automated backups and restricted database identity.
- Background worker/queue for event processing and alerts.
- Secret manager/KMS for API secrets and policy-signing key operations.
- Central logs/metrics and alerting.
- Static frontend hosting with security headers.
- Private release artifact storage for signed agent packages.

For a 6–20 person pilot, a single API instance and one background worker are sized to handle ~10–50 requests/minute. Do not expose PostgreSQL directly to the public internet.

## 3. Cost and Licensing Estimates (F-006)

*Estimated for a 6–20 endpoint deployment (Q4 2026 pricing baseline):*

| Component | Provider / SKU | Estimated Unit Cost | Estimated Total (Fleet of 10) |
|---|---|---|---|
| **Control Plane DB** | AWS RDS PostgreSQL `db.t4g.micro` or Azure B1ms | ~$25–$50 / month | ~$35 / month |
| **API & Worker Compute** | AWS Fargate (0.5 vCPU, 1 GB) or Azure Container Apps | ~$20–$40 / month | ~$30 / month |
| **Frontend & MSI Storage** | AWS S3 + CloudFront or Cloudflare Pages + R2 | ~$5–$15 / month | ~$10 / month |
| **KMS / Policy Signing** | AWS KMS (asymmetric key operations) / Azure Key Vault | ~$1–$3 / key / month | ~$3 / month |
| **Protected Audit Sink** | AWS S3 Object Lock (WORM) or CloudWatch Logs | ~$5–$15 / month | ~$10 / month |
| **Code Signing Certificate** | Public CA EV Code Signing Cert (DigiCert, Sectigo) | ~$500–$700 / year | ~$50 / month amortized |
| **Windows Fleet Licensing** | Microsoft 365 Business Premium (includes MDE, Intune, WDAC) | ~$22 / user / month | ~$220 / month |
| **Endpoint DLP Add-on** | Microsoft Purview DLP or third-party DLP provider | Optional: ~$8–$15 / seat / mo | ~$100 / month (Phase 4) |
| **Total Estimated Budget** | | | **~$358 / month** (pre-DLP)<br>**~$458 / month** (with DLP) |

## 4. DNS and TLS

- Use a company-owned domain and valid TLS certificates.
- Redirect HTTP to HTTPS; configure HSTS after verifying all routes.
- Keep admin API access behind identity and role checks; consider IP restrictions or an admin VPN if operationally appropriate.
- Separate public frontend, API, database and release artifact permissions.

## 5. Configuration and secrets

Use environment configuration for non-secret settings and a secret manager for credentials. `.env.example` is only a list of names; do not commit real `.env` files.

Required values should be validated at startup; fail closed if production security configuration is missing. No default admin password, hard-coded JWT secret, reusable agent token or default signing key is permitted.

## 6. Policy signing and agent releases

- Separate policy-signing authority from ordinary administrator accounts.
- Protect signing keys in a managed key service (AWS KMS, Azure Key Vault, or hardware HSM).
- Version and hash each immutable policy artifact as defined in [`SIGNING_SPEC.md`](SIGNING_SPEC.md).
- Sign agent binaries/installers with an EV Code Signing certificate and verify release digests/signatures before deployment.
- Publish to a pilot ring first; monitor errors before broad rollout.
- Keep a known-good signed release and a tested rollback path.

## 7. Backups and recovery

- Encrypt backups and restrict restore privileges.
- Back up database metadata/configuration and essential audit records; source code should follow the company's independent repository/backup design.
- Run a scheduled restore test and document recovery time/point objectives.
- Test recovery of policy-signing capability without placing private keys in backups unless the key service's documented recovery process requires it.

## 8. Observability and External SIEM / Audit Sink (F-017)

To prevent an adversary with control plane or database access from tampering with audit records, configure an external immutable log sink:
- **AWS Option:** Stream `admin_audit_events` and critical security events to Amazon S3 with **Object Lock in Compliance Mode** (WORM — Write Once, Read Many). Neither the application nor AWS account root can delete audit logs during the retention window. Alternatively, export to Amazon CloudWatch Logs with non-deletable log group resource policies.
- **Azure Option:** Export audit logs to Azure Blob Storage configured with **Immutable Blob Storage** (time-based retention policies).
- **SIEM Forwarder Option:** Configure a dedicated worker forwarder sending signed RFC 5424 syslog packets over mTLS to an enterprise SIEM (Datadog, Splunk, Elastic) using write-only ingest API keys.

Alert on:
- API/worker errors and high latency.
- Unusual agent enrollment attempts or failures.
- Device heartbeat beyond the approved warning threshold (`DEVICE_WARN_AFTER_SECONDS`).
- Signature failures, policy downgrade attempts and repeated enforcement failures.
- High-impact policy changes, exception creation, role changes and audit exports.
- Backup/restore failure and certificate/key expiry.

Ensure alerts have an owner, action runbook and test schedule.

## 9. Deployment gates

1. Approve threat model, telemetry notice ([`EMPLOYEE_NOTICE.md`](EMPLOYEE_NOTICE.md)) and data retention.
2. Verify staging tests on each supported Windows edition/build.
3. Confirm database backup restoration and key recovery procedure.
4. Confirm endpoint controls really enforce through native/provider mechanisms.
5. Pilot with non-production test data and written rollback criteria.
6. Obtain sign-off from IT/security and designated company decision-maker.
7. Roll out gradually, then review effectiveness and exception count.
