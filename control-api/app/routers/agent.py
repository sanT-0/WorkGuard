from fastapi import APIRouter, HTTPException, Header
import uuid, json, hashlib
from datetime import datetime, timezone, timedelta
from app.database import get_connection, utc_now_iso
from app.crypto import sign_envelope, SERVER_PUBLIC_KEY_HEX
from app.schemas import (
    AgentEnrollRequest, AgentEnrollResponse, AgentHeartbeatRequest,
    AgentPolicyResultsRequest, AgentEventsBatchRequest,
    AgentUpdatesCheckRequest, AgentReleaseCheckResponse
)

router = APIRouter(prefix="/agent", tags=["Agent"])

@router.post("/enroll", response_model=AgentEnrollResponse, status_code=201)
def agent_enroll(req: AgentEnrollRequest):
    code_hash = hashlib.sha256(req.enrollment_code.strip().encode("utf-8")).hexdigest()
    conn = get_connection()
    cur = conn.cursor()
    record = cur.execute("SELECT * FROM enrollment_codes WHERE code_hash = ?", (code_hash,)).fetchone()
    if not record:
        conn.close()
        raise HTTPException(status_code=401, detail="Invalid enrollment code")
    
    now = datetime.now(timezone.utc)
    exp = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
    if now > exp:
        conn.close()
        raise HTTPException(status_code=401, detail="Enrollment code has expired")
    if record["used_at"] is not None:
        conn.close()
        raise HTTPException(status_code=401, detail="Enrollment code has already been used")
    
    device_id = str(uuid.uuid4())
    display_name = f"WIN-{device_id[:6].upper()}-LAPTOP"
    now_iso = utc_now_iso()
    
    cur.execute(
        "INSERT INTO devices (id, display_name, assigned_user_id, os_version, os_edition, agent_version, status, last_seen_at, policy_version_desired, policy_version_observed, device_public_key, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 'enrolled', ?, 1, NULL, ?, ?)",
        (device_id, display_name, record["requested_for_user_id"], req.os_version, req.os_edition, req.agent_version, now_iso, req.device_public_key, now_iso)
    )
    cur.execute(
        "UPDATE enrollment_codes SET used_at = ?, used_by_device_id = ? WHERE code_hash = ?",
        (now_iso, device_id, code_hash)
    )
    cur.execute(
        "INSERT INTO admin_audit_events (id, actor_user_id, action, target_type, target_id, details_json, created_at) "
        "VALUES (?, 'agent', 'device.enroll', 'device', ?, ?, ?)",
        (str(uuid.uuid4()), device_id, f'{{"display_name": "{display_name}", "os": "{req.os_version}"}}', now_iso)
    )
    conn.commit()
    conn.close()
    return {
        "device_id": device_id,
        "credential_enrollment_uri": f"https://workguard.example/api/v1/agent/cert/{device_id}"
    }

@router.post("/heartbeat", status_code=202)
def agent_heartbeat(req: AgentHeartbeatRequest, x_device_id: str = Header("dev-sim-001")):
    conn = get_connection()
    cur = conn.cursor()
    dev = cur.execute("SELECT * FROM devices WHERE id = ?", (x_device_id,)).fetchone()
    if not dev:
        conn.close()
        raise HTTPException(status_code=401, detail="Unknown device")
    if dev["status"] == "revoked":
        conn.close()
        raise HTTPException(status_code=403, detail="Device has been revoked")
    
    now_iso = utc_now_iso()
    cur.execute(
        "UPDATE devices SET last_seen_at = ?, agent_version = ?, os_version = ?, policy_version_observed = ? WHERE id = ?",
        (now_iso, req.agent_version, req.os_version, req.current_policy_version, x_device_id)
    )
    conn.commit()
    conn.close()
    return {"status": "heartbeat_acknowledged", "last_seen_at": now_iso}

@router.get("/policies/current")
def get_current_policy(x_device_id: str = Header("dev-sim-001")):
    conn = get_connection()
    cur = conn.cursor()
    dev = cur.execute("SELECT * FROM devices WHERE id = ?", (x_device_id,)).fetchone()
    if not dev:
        conn.close()
        raise HTTPException(status_code=401, detail="Device not authenticated")
    if dev["status"] == "revoked":
        conn.close()
        raise HTTPException(status_code=403, detail="Device revoked")
    
    pv = cur.execute(
        "SELECT pv.*, p.id as pol_id FROM policy_versions pv "
        "JOIN policies p ON p.id = pv.policy_id "
        "WHERE p.lifecycle_state = 'published' "
        "ORDER BY pv.version DESC LIMIT 1"
    ).fetchone()
    if not pv:
        conn.close()
        raise HTTPException(status_code=204, detail="No published policy")
    
    policy_dict = json.loads(pv["policy_json"])
    now = datetime.now(timezone.utc)
    issued_at = now.isoformat()
    expires_at = (now + timedelta(days=1)).isoformat()
    
    envelope = {
        "policy_id": pv["policy_id"],
        "policy_version": pv["version"],
        "schema_version": "1.0.0",
        "issued_at": issued_at,
        "expires_at": expires_at,
        "target_device_id": x_device_id,
        "digest_sha256": pv["digest_sha256"],
        "algorithm": "Ed25519",
        "key_id": pv["key_id"],
        "signature": pv["signature_base64"],
        "policy": policy_dict
    }
    conn.close()
    return envelope

@router.post("/policy-results", status_code=202)
def post_policy_results(req: AgentPolicyResultsRequest, x_device_id: str = Header("dev-sim-001")):
    conn = get_connection()
    cur = conn.cursor()
    dev = cur.execute("SELECT * FROM devices WHERE id = ?", (x_device_id,)).fetchone()
    if not dev:
        conn.close()
        raise HTTPException(status_code=401, detail="Device not authenticated")
    
    for cr in req.controls:
        safe_det = cr.safe_details[:1000] if cr.safe_details else None
        res_id = str(uuid.uuid4())
        cur.execute(
            "INSERT INTO control_results (id, device_id, policy_version, control_id, status, provider, observed_at, error_code, safe_details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (res_id, x_device_id, req.policy_version, cr.control_id, cr.status, cr.provider, cr.observed_at, cr.error_code, safe_det)
        )
    
    statuses = [c.status for c in req.controls]
    if any(s == "failed" for s in statuses):
        new_status = "noncompliant"
    else:
        new_status = "compliant"
    
    cur.execute(
        "UPDATE devices SET status = ?, policy_version_observed = ?, last_seen_at = ? WHERE id = ?",
        (new_status, req.policy_version, req.observed_at, x_device_id)
    )
    conn.commit()
    conn.close()
    return {"status": "results_accepted", "derived_device_status": new_status}

@router.post("/events:batch", status_code=202)
def post_events_batch(req: AgentEventsBatchRequest, x_device_id: str = Header("dev-sim-001")):
    conn = get_connection()
    cur = conn.cursor()
    for ev in req.events:
        ev_id = ev.id or str(uuid.uuid4())
        cur.execute(
            "INSERT INTO security_events (id, device_id, event_type, severity, occurred_at, source, response_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ev_id, x_device_id, ev.event_type, ev.severity, ev.occurred_at, ev.source, ev.response_state)
        )
    conn.commit()
    conn.close()
    return {"status": "events_accepted", "count": len(req.events)}

@router.post("/updates/check", response_model=AgentReleaseCheckResponse)
def check_updates(req: AgentUpdatesCheckRequest):
    return {
        "update_available": False,
        "release_version": "1.0.0",
        "mandatory": False
    }
