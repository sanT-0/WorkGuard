from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.database import get_connection
from app.policy_verify import verify_envelope
from app.signing import jwks

SEEDED_POLICY_ID = "00000000-0000-4000-8000-000000000001"


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _policy_payload(client) -> dict:
    detail = client.get(
        f"/api/v1/admin/policies/{SEEDED_POLICY_ID}",
        headers={"X-Dev-Role": "security_admin"},
    ).json()
    return detail["policy"]


def _create_draft(client, policy, name="Probe policy"):
    return client.post(
        "/api/v1/admin/policies",
        json={"name": name, "policy": policy, "reason": "test draft"},
    )


def _lifecycle_to_published(client, policy_id, author="dev-admin"):
    assert client.post(
        f"/api/v1/admin/policies/{policy_id}/submit",
        headers={"X-Dev-User": author},
    ).status_code == 200
    assert client.post(
        f"/api/v1/admin/policies/{policy_id}/approve",
        headers={"X-Dev-User": "approver-2"},
        json={"approval_notes": 'approved with "quotes" and \\ backslash'},
    ).status_code == 200
    return client.post(
        f"/api/v1/admin/policies/{policy_id}/publish",
        headers={"X-Dev-User": "publisher-2"},
        json={"reason": "test release"},
    )


def test_health_and_root(client):
    assert client.get("/health/live").json()["status"] == "alive"
    assert client.get("/health/ready").json()["status"] == "ready"
    root = client.get("/api/v1").json()
    assert root["auth_mode"] == "dev"


def test_agent_requires_device_token(client):
    assert client.get("/api/v1/agent/policies/current").status_code == 401
    assert client.get(
        "/api/v1/agent/policies/current", headers={"X-Device-Id": "dev-sim-001"}
    ).status_code == 401


def test_policy_lifecycle_and_agent_envelope(client, agent_headers):
    policy = _policy_payload(client)
    created = _create_draft(client, policy)
    assert created.status_code == 201, created.text
    policy_id = created.json()["id"]

    # A draft cannot be published and cannot be approved before submission.
    assert client.post(
        f"/api/v1/admin/policies/{policy_id}/publish",
        headers={"X-Dev-User": "publisher-2"},
        json={"reason": "too early"},
    ).status_code == 409

    assert client.post(
        f"/api/v1/admin/policies/{policy_id}/submit"
    ).status_code == 200

    # The author cannot be the approver.
    assert client.post(
        f"/api/v1/admin/policies/{policy_id}/approve",
        json={"approval_notes": "self approval"},
    ).status_code == 403

    approved = client.post(
        f"/api/v1/admin/policies/{policy_id}/approve",
        headers={"X-Dev-User": "approver-2"},
        json={"approval_notes": "second person"},
    )
    assert approved.status_code == 200, approved.text

    published = client.post(
        f"/api/v1/admin/policies/{policy_id}/publish",
        headers={"X-Dev-User": "publisher-2"},
        json={"reason": "release"},
    )
    assert published.status_code == 202, published.text
    assert published.json()["version"] == 1

    detail = client.get(f"/api/v1/admin/policies/{policy_id}").json()
    assert [item["version"] for item in detail["versions"]] == [1]
    assert detail["lifecycle_state"] == "published"

    envelope = client.get(
        "/api/v1/agent/policies/current", headers=agent_headers
    ).json()
    assert envelope["policy_id"] == policy_id
    assert envelope["policy_version"] == 1
    assert envelope["policy"]["policy_version"] == 1
    result = verify_envelope(envelope, jwks(), "dev-sim-001", last_applied_version=0)
    assert result.policy_version == 1

    # A new draft creates version 2; publishing must not create version 3.
    draft = client.post(f"/api/v1/admin/policies/{policy_id}/new-draft")
    assert draft.status_code == 201, draft.text
    assert draft.json()["draft_version"] == 2
    assert client.post(
        f"/api/v1/admin/policies/{policy_id}/publish",
        headers={"X-Dev-User": "publisher-2"},
        json={"reason": "no approval"},
    ).status_code == 409
    assert _lifecycle_to_published(client, policy_id).json()["version"] == 2

    detail = client.get(f"/api/v1/admin/policies/{policy_id}").json()
    assert [item["version"] for item in detail["versions"]] == [2, 1]
    envelope = client.get(
        "/api/v1/agent/policies/current", headers=agent_headers
    ).json()
    assert envelope["policy_version"] == 2
    verify_envelope(envelope, jwks(), "dev-sim-001", last_applied_version=1)


def test_rollback_creates_a_new_monotonic_version(client, agent_headers):
    policy = _policy_payload(client)
    policy_id = _create_draft(client, policy).json()["id"]
    _lifecycle_to_published(client, policy_id)

    # Create a second published version, then roll back to version 1.
    client.post(f"/api/v1/admin/policies/{policy_id}/new-draft")
    _lifecycle_to_published(client, policy_id)
    rollback = client.post(
        f"/api/v1/admin/policies/{policy_id}/rollback",
        headers={"X-Dev-User": "publisher-2"},
        json={"target_version": 1, "reason": "rollback test"},
    )
    assert rollback.status_code == 202, rollback.text
    assert rollback.json()["version"] == 3
    assert rollback.json()["rollback_of_version"] == 1

    envelope = client.get(
        "/api/v1/agent/policies/current", headers=agent_headers
    ).json()
    assert envelope["policy_version"] == 3
    verify_envelope(envelope, jwks(), "dev-sim-001", last_applied_version=2)


def test_rollback_rejects_a_pending_draft(client, agent_headers):
    policy = _policy_payload(client)
    policy_id = _create_draft(client, policy).json()["id"]
    _lifecycle_to_published(client, policy_id)

    # The author cannot use rollback as a publish-equivalent action.
    assert client.post(
        f"/api/v1/admin/policies/{policy_id}/rollback",
        headers={"X-Dev-User": "dev-admin"},
        json={"target_version": 1, "reason": "author rollback"},
    ).status_code == 403

    assert client.post(
        f"/api/v1/admin/policies/{policy_id}/new-draft"
    ).status_code == 201
    assert client.post(
        f"/api/v1/admin/policies/{policy_id}/submit"
    ).status_code == 200

    # A pending draft must not take the published version away from devices.
    envelope = client.get(
        "/api/v1/agent/policies/current", headers=agent_headers
    ).json()
    assert envelope["policy_id"] == policy_id
    assert envelope["policy_version"] == 1

    # The pending draft must not be publishable through the rollback path.
    rollback = client.post(
        f"/api/v1/admin/policies/{policy_id}/rollback",
        headers={"X-Dev-User": "publisher-2"},
        json={"target_version": 2, "reason": "attempt to bypass approval"},
    )
    assert rollback.status_code == 409
    detail = client.get(f"/api/v1/admin/policies/{policy_id}").json()
    assert detail["version"] == 1
    assert detail["lifecycle_state"] == "submitted"


def test_publishing_a_new_version_requires_fresh_readback(client, agent_headers):
    policy = _policy_payload(client)
    policy_id = _create_draft(client, policy).json()["id"]
    _lifecycle_to_published(client, policy_id)

    controls = [
        {
            "control_id": control["control_id"],
            "status": "enforced",
            "provider": "test provider",
            "observed_at": _now(),
        }
        for control in policy["controls"]
    ]
    assert client.post(
        "/api/v1/agent/policy-results",
        headers=agent_headers,
        json={"policy_version": 1, "observed_at": _now(), "controls": controls},
    ).json()["derived_device_status"] == "compliant"

    client.post(f"/api/v1/admin/policies/{policy_id}/new-draft")
    _lifecycle_to_published(client, policy_id)

    # Version 2 is now desired.  The v1 read-back must not keep the device
    # compliant, and the detail view must not show the stale v1 controls.
    detail = client.get("/api/v1/admin/devices/dev-sim-001").json()
    assert detail["status"] == "noncompliant"
    assert detail["policy_version_desired"] == 2
    assert detail["controls"] == []

    # A heartbeat cannot move the observed version backwards either.
    for observed in (2, 1):
        heartbeat = client.post(
            "/api/v1/agent/heartbeat",
            headers=agent_headers,
            json={
                "agent_version": "1.1.0",
                "os_version": "Windows 11 Enterprise (23H2)",
                "observed_at": _now(),
                "current_policy_version": observed,
            },
        )
        assert heartbeat.status_code == 202
    detail = client.get("/api/v1/admin/devices/dev-sim-001").json()
    assert detail["policy_version_observed"] == 2

    fresh = client.post(
        "/api/v1/agent/policy-results",
        headers=agent_headers,
        json={"policy_version": 2, "observed_at": _now(), "controls": controls},
    )
    assert fresh.json()["derived_device_status"] == "compliant"


def test_invalid_pagination_cursor_returns_422(client):
    for path in (
        "/api/v1/admin/devices",
        "/api/v1/admin/events",
        "/api/v1/admin/audit-events",
        "/api/v1/admin/exceptions",
    ):
        response = client.get(f"{path}?cursor=not-a-cursor")
        assert response.status_code == 422, (path, response.text)
        assert response.json()["error"]["code"] == "INVALID_CURSOR"


def test_invalid_policy_settings_are_rejected(client):
    policy = _policy_payload(client)
    policy["controls"][0]["settings"]["action"] = "allow-everything"
    response = _create_draft(client, policy)
    assert response.status_code == 422
    assert "action" in response.text


def test_rbac_and_dev_identity(client):
    assert client.get(
        "/api/v1/admin/devices", headers={"X-Dev-Role": "auditor"}
    ).status_code == 200
    assert client.get(
        "/api/v1/admin/devices/dev-sim-001", headers={"X-Dev-Role": "auditor"}
    ).status_code == 200
    assert client.get(
        "/api/v1/admin/policies", headers={"X-Dev-Role": "auditor"}
    ).status_code == 200
    assert client.post(
        "/api/v1/admin/enrollment-codes",
        headers={"X-Dev-Role": "auditor"},
        json={"reason": "should fail"},
    ).status_code == 403
    assert client.get(
        "/api/v1/admin/devices", headers={"X-Dev-Role": "it_operator"}
    ).status_code == 200


def test_device_events_and_results(client, agent_headers):
    envelope = client.get(
        "/api/v1/agent/policies/current", headers=agent_headers
    ).json()
    version = envelope["policy_version"]

    unknown = client.post(
        "/api/v1/agent/policy-results",
        headers=agent_headers,
        json={
            "policy_version": version,
            "observed_at": _now(),
            "controls": [
                {
                    "control_id": "not_a_control",
                    "status": "enforced",
                    "provider": "probe",
                    "observed_at": _now(),
                }
            ],
        },
    )
    assert unknown.status_code == 422

    unsupported = client.post(
        "/api/v1/agent/policy-results",
        headers=agent_headers,
        json={
            "policy_version": version,
            "observed_at": _now(),
            "controls": [
                {
                    "control_id": "application_control",
                    "status": "unsupported",
                    "provider": "AppLocker",
                    "observed_at": _now(),
                }
            ],
        },
    )
    assert unsupported.status_code == 202
    assert unsupported.json()["derived_device_status"] == "noncompliant"

    controls = [
        {
            "control_id": control["control_id"],
            "status": "enforced",
            "provider": "test provider",
            "observed_at": _now(),
        }
        for control in envelope["policy"]["controls"]
    ]
    compliant = client.post(
        "/api/v1/agent/policy-results",
        headers=agent_headers,
        json={
            "policy_version": version,
            "observed_at": _now(),
            "controls": controls,
        },
    )
    assert compliant.status_code == 202
    assert compliant.json()["derived_device_status"] == "compliant"

    event = {
        "event_type": "usb.device.blocked",
        "severity": "high",
        "occurred_at": _now(),
        "source": "removable_storage",
        "response_state": "blocked",
    }
    accepted = client.post(
        "/api/v1/agent/events:batch",
        headers=agent_headers,
        json={"events": [event]},
    )
    assert accepted.status_code == 202
    assert accepted.json()["count"] == 1

    wrong_device = client.post(
        "/api/v1/agent/events:batch",
        headers=agent_headers,
        json={"events": [{**event, "device_id": "dev-sim-002"}]},
    )
    assert wrong_device.status_code == 403

    duplicate = {**event, "id": "dedupe-test-1"}
    assert client.post(
        "/api/v1/agent/events:batch", headers=agent_headers, json={"events": [duplicate]}
    ).json()["count"] == 1
    assert client.post(
        "/api/v1/agent/events:batch", headers=agent_headers, json={"events": [duplicate]}
    ).json()["count"] == 0

    too_many = client.post(
        "/api/v1/agent/events:batch",
        headers=agent_headers,
        json={"events": [event for _ in range(101)]},
    )
    assert too_many.status_code == 413


def test_exceptions_validate_scope_and_expiry(client):
    valid = {
        "device_id": "dev-sim-001",
        "control_id": "removable_storage",
        "reason": "approved USB transfer for a customer demo",
        "expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    }
    created = client.post("/api/v1/admin/exceptions", json=valid)
    assert created.status_code == 201, created.text
    exception_id = created.json()["id"]

    assert client.post(
        "/api/v1/admin/exceptions",
        json={**valid, "control_id": "not_a_control"},
    ).status_code == 422
    assert client.post(
        "/api/v1/admin/exceptions",
        json={**valid, "expires_at": "2020-01-01T00:00:00+00:00"},
    ).status_code == 422

    listing = client.get("/api/v1/admin/exceptions").json()
    assert any(item["id"] == exception_id for item in listing["items"])

    revoked = client.post(
        f"/api/v1/admin/exceptions/{exception_id}/revoke",
        json={"reason": "demo ended"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"


def test_exception_covers_unenforced_control(client, agent_headers):
    exception = client.post(
        "/api/v1/admin/exceptions",
        json={
            "device_id": "dev-sim-001",
            "control_id": "application_control",
            "reason": "application control exception for an approved pilot",
            "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        },
    )
    assert exception.status_code == 201, exception.text

    duplicate = client.post(
        "/api/v1/admin/exceptions",
        json={
            "device_id": "dev-sim-001",
            "control_id": "application_control",
            "reason": "duplicate exception attempt",
            "expires_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        },
    )
    assert duplicate.status_code == 409

    response = client.post(
        "/api/v1/agent/policy-results",
        headers=agent_headers,
        json={
            "policy_version": 1,
            "observed_at": _now(),
            "controls": [
                {
                    "control_id": "application_control",
                    "status": "unsupported",
                    "provider": "AppLocker",
                    "observed_at": _now(),
                }
            ],
        },
    )
    assert response.status_code == 202, response.text
    assert response.json()["derived_device_status"] == "compliant"

    detail = client.get("/api/v1/admin/devices/dev-sim-001").json()
    excepted = [
        item
        for item in detail["compliance_details"]
        if item["control_id"] == "application_control"
    ]
    assert excepted and excepted[0]["status"] == "excepted"
    assert excepted[0]["exception_id"] == exception.json()["id"]


def test_results_for_old_version_do_not_satisfy_new_policy(client, agent_headers):
    assert client.post(
        f"/api/v1/admin/policies/{SEEDED_POLICY_ID}/new-draft"
    ).status_code == 201
    assert _lifecycle_to_published(client, SEEDED_POLICY_ID).json()["version"] == 2

    envelope = client.get(
        "/api/v1/agent/policies/current", headers=agent_headers
    ).json()
    assert envelope["policy_version"] == 2
    controls = [
        {
            "control_id": control["control_id"],
            "status": "enforced",
            "provider": "test provider",
            "observed_at": _now(),
        }
        for control in envelope["policy"]["controls"]
    ]

    # Results for the previously applied version are accepted for the record,
    # but must not satisfy the newly desired version.
    stale = client.post(
        "/api/v1/agent/policy-results",
        headers=agent_headers,
        json={"policy_version": 1, "observed_at": _now(), "controls": controls},
    )
    assert stale.status_code == 202, stale.text
    assert stale.json()["derived_device_status"] == "noncompliant"

    fresh = client.post(
        "/api/v1/agent/policy-results",
        headers=agent_headers,
        json={"policy_version": 2, "observed_at": _now(), "controls": controls},
    )
    assert fresh.status_code == 202, fresh.text
    assert fresh.json()["derived_device_status"] == "compliant"


def test_audit_chain_detects_tampering(client):
    verify = client.get("/api/v1/admin/audit-events/verify").json()
    assert verify["valid"] is True

    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT id FROM admin_audit_events WHERE record_hash IS NOT NULL "
            "ORDER BY rowid DESC LIMIT 1"
        ).fetchone()
        conn.execute(
            "UPDATE admin_audit_events SET details_json = ? WHERE id = ?",
            ('{"tampered":true}', row["id"]),
        )
        conn.commit()
    finally:
        conn.close()

    verify = client.get("/api/v1/admin/audit-events/verify").json()
    assert verify["valid"] is False


def test_stale_device_is_marked_and_recovers(client, agent_headers):
    conn = get_connection()
    try:
        old = (datetime.now(UTC) - timedelta(hours=2)).isoformat()
        conn.execute(
            "UPDATE devices SET last_seen_at = ?, status = 'compliant' WHERE id = 'dev-sim-001'",
            (old,),
        )
        conn.commit()
    finally:
        conn.close()

    devices = client.get("/api/v1/admin/devices").json()["items"]
    target = next(item for item in devices if item["id"] == "dev-sim-001")
    assert target["status"] == "stale"

    heartbeat = client.post(
        "/api/v1/agent/heartbeat",
        headers=agent_headers,
        json={
            "agent_version": "1.1.0",
            "os_version": "Windows 11 Enterprise (23H2)",
            "observed_at": _now(),
            "current_policy_version": 1,
        },
    )
    assert heartbeat.status_code == 202
    target = client.get("/api/v1/admin/devices/dev-sim-001").json()
    assert target["status"] != "stale"


def test_audit_details_survive_quotes(client):
    policy = _policy_payload(client)
    policy_id = _create_draft(client, policy).json()["id"]
    client.post(f"/api/v1/admin/policies/{policy_id}/submit")
    client.post(
        f"/api/v1/admin/policies/{policy_id}/approve",
        headers={"X-Dev-User": "approver-2"},
        json={"approval_notes": 'he said "yes" and \\ left'},
    )
    audit = client.get("/api/v1/admin/audit-events?action=policy.approved").json()
    notes = [item["details"].get("notes") for item in audit["items"]]
    assert 'he said "yes" and \\ left' in notes
