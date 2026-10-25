from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import uuid, hashlib, secrets
from datetime import datetime, timezone, timedelta
from app.database import get_connection, utc_now_iso
from app.schemas import DeviceSummary, DeviceDetail, CreateEnrollmentCodeRequest, EnrollmentCodeResponse, RevokeDeviceRequest

router = APIRouter(prefix="/admin", tags=["Admin Devices"])

@router.get("/devices")
def list_devices(
    cursor: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None)
):
    conn = get_connection()
    cur = conn.cursor()
    query = "SELECT * FROM devices"
    params = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = cur.execute(query, params).fetchall()
    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "display_name": r["display_name"],
            "assigned_user_id": r["assigned_user_id"],
            "os_version": r["os_version"],
            "os_edition": r["os_edition"],
            "agent_version": r["agent_version"],
            "status": r["status"],
            "last_seen_at": r["last_seen_at"]
        })
    conn.close()
    return {"items": items, "next_cursor": None}

@router.get("/devices/{device_id}", response_model=DeviceDetail)
def get_device(device_id: str):
    conn = get_connection()
    cur = conn.cursor()
    row = cur.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    
    controls_rows = cur.execute(
        "SELECT * FROM control_results WHERE device_id = ? ORDER BY observed_at DESC", (device_id,)
    ).fetchall()
    controls = []
    seen_cids = set()
    for cr in controls_rows:
        cid = cr["control_id"]
        if cid not in seen_cids:
            seen_cids.add(cid)
            controls.append({
                "control_id": cr["control_id"],
                "status": cr["status"],
                "provider": cr["provider"],
                "observed_at": cr["observed_at"],
                "error_code": cr["error_code"],
                "safe_details": cr["safe_details"]
            })
    conn.close()
    return {
        "id": row["id"],
        "display_name": row["display_name"],
        "assigned_user_id": row["assigned_user_id"],
        "os_version": row["os_version"],
        "os_edition": row["os_edition"],
        "agent_version": row["agent_version"],
        "status": row["status"],
        "last_seen_at": row["last_seen_at"],
        "policy_version_desired": row["policy_version_desired"],
        "policy_version_observed": row["policy_version_observed"],
        "controls": controls
    }

@router.post("/devices/{device_id}/revoke")
def revoke_device(device_id: str, req: RevokeDeviceRequest):
    conn = get_connection()
    cur = conn.cursor()
    row = cur.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    
    cur.execute("UPDATE devices SET status = 'revoked' WHERE id = ?", (device_id,))
    audit_id = str(uuid.uuid4())
    cur.execute(
        "INSERT INTO admin_audit_events (id, actor_user_id, action, target_type, target_id, details_json, created_at) "
        "VALUES (?, ?, 'device.revoke', 'device', ?, ?, ?)",
        (audit_id, "admin-system", device_id, f'{{"reason": "{req.reason}"}}', utc_now_iso())
    )
    conn.commit()
    revoked = cur.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    conn.close()
    return dict(revoked)

@router.post("/enrollment-codes", response_model=EnrollmentCodeResponse, status_code=201)
def create_enrollment_code(req: CreateEnrollmentCodeRequest):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    raw_code = "WG-" + "".join(secrets.choice(alphabet) for _ in range(24))
    code_hash = hashlib.sha256(raw_code.encode("utf-8")).hexdigest()
    
    expires_at = (datetime.now(timezone.utc) + timedelta(seconds=req.expires_in_seconds)).isoformat()
    now_iso = utc_now_iso()
    
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO enrollment_codes (code_hash, requested_for_user_id, reason, expires_at, created_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (code_hash, req.requested_for_user_id, req.reason, expires_at, now_iso)
    )
    conn.commit()
    conn.close()
    return {"enrollment_code": raw_code, "expires_at": expires_at}
