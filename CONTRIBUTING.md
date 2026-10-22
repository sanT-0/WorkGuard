# Contributing to WorkGuard

## Development rules

- Read `ARCHITECTURE.md` and `SECURITY.md` before changing enforcement or identity code.
- Keep source-code contents out of telemetry and tests unless a specifically approved local fixture is required.
- Use typed policy models and finite control IDs; no arbitrary remote shell/PowerShell command execution.
- Add tests for both allowed and denied behavior for any authorization/policy change.
- Update `API.md`, `openapi.yaml`, schemas and data model in the same change when contracts evolve.
- Prefer OS/vendor-supported enforcement interfaces. A UI toggle is not enforcement.
- Include rollback and upgrade behavior for endpoint-agent changes.
- Keep secrets out of commits, issues, test output and screenshots.

## Pull request checklist

- [ ] Threat model updated if the trust boundary or telemetry changes.
- [ ] Unit/integration/security tests pass.
- [ ] Tenant/object authorization tests included where applicable.
- [ ] Logging is bounded and redacted.
- [ ] Policy/version compatibility documented.
- [ ] Rollback/recovery steps documented.
- [ ] Employee-facing behavior and [`EMPLOYEE_NOTICE.md`](EMPLOYEE_NOTICE.md) updated if telemetry, monitoring scope, or data retention changes.
- [ ] **Mandatory HR/Legal review sign-off** obtained for any PR that expands employee telemetry fields, event logging, or data collection scope (F-018).
- [ ] Windows platform/edition support and provider limitations documented in [`ENDPOINT_AGENT.md`](ENDPOINT_AGENT.md).
