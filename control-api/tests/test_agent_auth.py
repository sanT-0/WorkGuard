from __future__ import annotations

import json

from app import config


def _token_for(device_id: str) -> str:
    tokens = json.loads(config.DEVICE_TOKEN_FILE.read_text(encoding="utf-8"))
    return tokens[device_id]


def test_bad_token_is_rejected(client):
    assert client.get(
        "/api/v1/agent/policies/current",
        headers={"Authorization": "Bearer not-a-real-token"},
    ).status_code == 401


def test_revoked_device_is_rejected(client):
    token = _token_for("dev-sim-002")
    headers = {"Authorization": f"Bearer {token}"}
    assert client.post(
        "/api/v1/agent/heartbeat",
        headers=headers,
        json={
            "agent_version": "1.1.0",
            "os_version": "Windows 11",
            "current_policy_version": 1,
            "observed_at": "2026-10-25T00:00:00+00:00",
        },
    ).status_code == 202

    revoked = client.post(
        "/api/v1/admin/devices/dev-sim-002/revoke",
        json={"reason": "lost device"},
    )
    assert revoked.status_code == 200

    # Revocation clears the stored credential hash, so the token stops
    # authenticating immediately (401) rather than reaching the 403 branch.
    assert client.get("/api/v1/agent/policies/current", headers=headers).status_code == 401
    assert client.get(
        "/api/v1/admin/devices/dev-sim-002"
    ).json()["status"] == "revoked"


def test_credential_rotation_invalidates_old_token(client):
    old_token = _token_for("dev-sim-003")
    old_headers = {"Authorization": f"Bearer {old_token}"}

    rotated = client.post("/api/v1/admin/devices/dev-sim-003/rotate-credential")
    assert rotated.status_code == 200
    new_token = rotated.json()["device_token"]
    assert new_token != old_token

    assert client.get(
        "/api/v1/agent/policies/current", headers=old_headers
    ).status_code == 401
    assert client.get(
        "/api/v1/agent/policies/current",
        headers={"Authorization": f"Bearer {new_token}"},
    ).status_code == 200


def test_enrollment_requires_auth_and_is_single_use(client):
    created = client.post(
        "/api/v1/admin/enrollment-codes",
        json={"reason": "new engineer laptop"},
    )
    assert created.status_code == 201
    code = created.json()["enrollment_code"]
    assert len(code.replace("WG-", "")) >= 26

    payload = {
        "enrollment_code": code,
        "agent_version": "1.1.0",
        "os_version": "Windows 11 Enterprise (23H2)",
        "os_edition": "Windows 11 Enterprise",
    }
    first = client.post("/api/v1/agent/enroll", json=payload)
    assert first.status_code == 201, first.text
    device_id = first.json()["device_id"]
    token = first.json()["device_token"]

    # Newly enrolled devices receive an assignment and can fetch a policy.
    envelope = client.get(
        "/api/v1/agent/policies/current",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert envelope.status_code == 200
    assert envelope.json()["target_device_id"] == device_id

    # The code is consumed and cannot be replayed.
    assert client.post("/api/v1/agent/enroll", json=payload).status_code == 401
