from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from app.audit import write_audit
from app.compliance import derive_compliance, refresh_stale_devices
from app.database import decode_cursor, encode_cursor, get_connection, utc_now_iso
from app.schemas import (
    CreateEnrollmentCodeRequest,
    DeviceDetail,
    EnrollmentCodeResponse,
    RevokeDeviceRequest,
    RotateDeviceCredentialResponse,
)
from app.security import (
    Principal,
    generate_device_token,
    generate_enrollment_code,
    hash_device_token,
    hash_enrollment_code,
    require_role,
)

router = APIRouter(prefix="/admin", tags=["Admin Devices"])


def _device_summary(row) -> dict:
    return {
        "id": row["id"],
        "org_id": row["org_id"],
        "display_name": row["display_name"],
        "assigned_user_id": row["assigned_user_id"],
        "os_version": row["os_version"],
        "os_edition": row["os_edition"],
        "agent_version": row["agent_version"],
        "status": row["status"],
        "last_seen_at": row["last_seen_at"],
        "policy_version_desired": row["policy_version_desired"],
        "policy_version_observed": row["policy_version_observed"],
        "last_applied_version": row["last_applied_version"],
    }


@router.get("/devices")
def list_devices(
    cursor: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    status: str | None = Query(None),
    principal: Annotated[Principal, Depends(require_role("auditor"))] = None,
):
    conn = get_connection()
    try:
        refresh_stale_devices(conn)
        query = "SELECT * FROM devices WHERE 1=1"
        params: list = []
        if status:
            query += " AND status = ?"
            params.append(status)
        decoded = decode_cursor(cursor)
        if decoded:
            created_at, row_id = decoded
            query += (
                " AND (created_at < ? OR (created_at = ? AND id < ?))"
            )
            params.extend([created_at, created_at, row_id])
        query += " ORDER BY created_at DESC, id DESC LIMIT ?"
        params.append(limit + 1)
        rows = conn.execute(query, params).fetchall()
        conn.commit()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = [_device_summary(row) for row in rows]
        next_cursor = None
        if has_more and rows:
            next_cursor = encode_cursor(rows[-1]["created_at"], rows[-1]["id"])
        return {"items": items, "next_cursor": next_cursor}
    finally:
        conn.close()


@router.get("/devices/{device_id}", response_model=DeviceDetail)
def get_device(
    device_id: str,
    principal: Annotated[Principal, Depends(require_role("auditor"))] = None,
):
    conn = get_connection()
    try:
        refresh_stale_devices(conn)
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Device not found")

        assignment = conn.execute(
            "SELECT policy_id, desired_version FROM device_policy_assignments "
            "WHERE device_id = ?",
            (device_id,),
        ).fetchone()
        desired_version = assignment["desired_version"] if assignment else None
        if desired_version is None:
            control_rows = conn.execute(
                "SELECT * FROM control_results WHERE device_id = ? "
                "ORDER BY observed_at DESC, rowid DESC",
                (device_id,),
            ).fetchall()
        else:
            # The detail view shows the read-back for the version the device is
            # supposed to be running, not a stale result from an older policy.
            control_rows = conn.execute(
                "SELECT * FROM control_results WHERE device_id = ? "
                "AND policy_version = ? ORDER BY observed_at DESC, rowid DESC",
                (device_id, desired_version),
            ).fetchall()
        controls = []
        seen = set()
        for control in control_rows:
            if control["control_id"] in seen:
                continue
            seen.add(control["control_id"])
            controls.append(
                {
                    "control_id": control["control_id"],
                    "status": control["status"],
                    "provider": control["provider"],
                    "observed_at": control["observed_at"],
                    "error_code": control["error_code"],
                    "safe_details": control["safe_details"],
                }
            )

        _, compliance_details = derive_compliance(conn, device_id)
        conn.commit()

        payload = _device_summary(row)
        payload.update(
            {
                "controls": controls,
                "assigned_policy_id": assignment["policy_id"] if assignment else None,
                "compliance_details": compliance_details,
            }
        )
        return payload
    finally:
        conn.close()


@router.post("/devices/{device_id}/revoke")
def revoke_device(
    device_id: str,
    req: RevokeDeviceRequest,
    principal: Annotated[Principal, Depends(require_role("security_admin"))] = None,
):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Device not found")

        now = utc_now_iso()
        conn.execute(
            "UPDATE devices SET status = 'revoked', credential_hash = NULL, "
            "credential_issued_at = NULL WHERE id = ?",
            (device_id,),
        )
        conn.execute(
            "UPDATE policy_exceptions SET status = 'revoked', revoked_at = ?, "
            "revoked_reason = 'Device revoked' "
            "WHERE device_id = ? AND status = 'active'",
            (now, device_id),
        )
        write_audit(
            conn,
            actor=principal.user_id,
            action="device.revoked",
            target_type="device",
            target_id=device_id,
            details={"reason": req.reason},
        )
        conn.commit()
        updated = conn.execute(
            "SELECT * FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        return _device_summary(updated)
    finally:
        conn.close()


@router.post(
    "/devices/{device_id}/rotate-credential",
    response_model=RotateDeviceCredentialResponse,
)
def rotate_device_credential(
    device_id: str,
    principal: Annotated[Principal, Depends(require_role("security_admin"))] = None,
):
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Device not found")
        if row["status"] == "revoked":
            raise HTTPException(status_code=409, detail="Revoked devices cannot receive credentials")

        token = generate_device_token()
        issued = utc_now_iso()
        conn.execute(
            "UPDATE devices SET credential_hash = ?, credential_issued_at = ? WHERE id = ?",
            (hash_device_token(token), issued, device_id),
        )
        write_audit(
            conn,
            actor=principal.user_id,
            action="device.credential_rotated",
            target_type="device",
            target_id=device_id,
            details={"issued_at": issued},
        )
        conn.commit()
        return {"device_id": device_id, "device_token": token, "issued_at": issued}
    finally:
        conn.close()


@router.post("/enrollment-codes", response_model=EnrollmentCodeResponse, status_code=201)
def create_enrollment_code(
    req: CreateEnrollmentCodeRequest,
    principal: Annotated[Principal, Depends(require_role("security_admin"))] = None,
):
    raw_code = generate_enrollment_code()
    code_hash = hash_enrollment_code(raw_code)
    expires_at = (
        datetime.now(UTC) + timedelta(seconds=req.expires_in_seconds)
    ).isoformat()

    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO enrollment_codes "
            "(code_hash, requested_for_user_id, reason, expires_at, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                code_hash,
                req.requested_for_user_id,
                req.reason,
                expires_at,
                utc_now_iso(),
            ),
        )
        write_audit(
            conn,
            actor=principal.user_id,
            action="device.enrollment_code_created",
            target_type="enrollment_code",
            target_id=code_hash[:16],
            details={
                "expires_at": expires_at,
                "requested_for_user_id": req.requested_for_user_id,
                "reason": req.reason,
            },
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "enrollment_code": raw_code,
        "expires_at": expires_at,
        "requested_for_user_id": req.requested_for_user_id,
    }
