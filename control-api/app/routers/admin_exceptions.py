from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query

from app.audit import write_audit
from app.compliance import get_assigned_policy
from app.database import decode_cursor, encode_cursor, get_connection, utc_now_iso
from app.schemas import (
    CreateExceptionRequest,
    ExceptionSummary,
    RevokeExceptionRequest,
)
from app.security import Principal, require_role
from app.validation import policy_control_ids

router = APIRouter(prefix="/admin/exceptions", tags=["Admin Exceptions"])


def _parse_expiry(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="expires_at must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise HTTPException(status_code=422, detail="expires_at must include a UTC offset")
    parsed = parsed.astimezone(UTC)
    now = datetime.now(UTC)
    if parsed <= now:
        raise HTTPException(status_code=422, detail="expires_at must be in the future")
    if parsed > now + timedelta(days=90):
        raise HTTPException(status_code=422, detail="Exceptions may last at most 90 days")
    return parsed


def _row_summary(row) -> dict:
    return {
        "id": row["id"],
        "device_id": row["device_id"],
        "control_id": row["control_id"],
        "reason": row["reason"],
        "status": row["status"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "revoked_at": row["revoked_at"],
        "revoked_reason": row["revoked_reason"],
    }


@router.get("")
def list_exceptions(
    cursor: str | None = Query(None),
    device_id: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    principal: Annotated[Principal, Depends(require_role("auditor"))] = None,
):
    conn = get_connection()
    try:
        now = utc_now_iso()
        conn.execute(
            "UPDATE policy_exceptions SET status = 'expired' "
            "WHERE status = 'active' AND expires_at < ?",
            (now,),
        )
        query = "SELECT * FROM policy_exceptions WHERE 1=1"
        params: list = []
        if device_id:
            query += " AND device_id = ?"
            params.append(device_id)
        if status:
            query += " AND status = ?"
            params.append(status)
        decoded = decode_cursor(cursor)
        if decoded:
            created_at, row_id = decoded
            query += " AND (created_at < ? OR (created_at = ? AND id < ?))"
            params.extend([created_at, created_at, row_id])
        query += " ORDER BY created_at DESC, id DESC LIMIT ?"
        params.append(limit + 1)
        rows = conn.execute(query, params).fetchall()
        conn.commit()
        has_more = len(rows) > limit
        rows = rows[:limit]
        next_cursor = None
        if has_more and rows:
            next_cursor = encode_cursor(rows[-1]["created_at"], rows[-1]["id"])
        return {"items": [_row_summary(row) for row in rows], "next_cursor": next_cursor}
    finally:
        conn.close()


@router.post("", response_model=ExceptionSummary, status_code=201)
def create_exception(
    req: CreateExceptionRequest,
    principal: Annotated[Principal, Depends(require_role("security_admin"))] = None,
):
    conn = get_connection()
    try:
        device = conn.execute("SELECT * FROM devices WHERE id = ?", (req.device_id,)).fetchone()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        if device["status"] == "revoked":
            raise HTTPException(status_code=409, detail="Cannot create an exception for a revoked device")

        expiry = _parse_expiry(req.expires_at)
        assignment = get_assigned_policy(conn, req.device_id)
        if assignment is None:
            raise HTTPException(status_code=409, detail="Device has no assigned policy")
        allowed_controls = policy_control_ids(assignment["policy"])
        if req.control_id not in allowed_controls:
            raise HTTPException(
                status_code=422,
                detail=f"control_id must be one of: {', '.join(sorted(allowed_controls))}",
            )

        now = utc_now_iso()
        active = conn.execute(
            "SELECT id FROM policy_exceptions WHERE device_id = ? AND control_id = ? "
            "AND status = 'active' AND expires_at > ?",
            (req.device_id, req.control_id, now),
        ).fetchone()
        if active is not None:
            raise HTTPException(
                status_code=409,
                detail="An active exception already exists for this device and control",
            )

        exception_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO policy_exceptions "
            "(id, device_id, control_id, reason, status, created_at, expires_at) "
            "VALUES (?, ?, ?, ?, 'active', ?, ?)",
            (exception_id, req.device_id, req.control_id, req.reason, now, expiry.isoformat()),
        )
        write_audit(
            conn,
            actor=principal.user_id,
            action="exception.created",
            target_type="exception",
            target_id=exception_id,
            details={
                "device_id": req.device_id,
                "control_id": req.control_id,
                "expires_at": expiry.isoformat(),
                "reason": req.reason,
            },
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM policy_exceptions WHERE id = ?", (exception_id,)
        ).fetchone()
        return _row_summary(row)
    finally:
        conn.close()


@router.post("/{exception_id}/revoke")
def revoke_exception(
    exception_id: str,
    req: RevokeExceptionRequest,
    principal: Annotated[Principal, Depends(require_role("security_admin"))] = None,
):
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM policy_exceptions WHERE id = ?", (exception_id,)
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Exception not found")
        if row["status"] == "revoked":
            return {"status": "revoked", "exception_id": exception_id}

        now = utc_now_iso()
        conn.execute(
            "UPDATE policy_exceptions SET status = 'revoked', revoked_at = ?, "
            "revoked_reason = ? WHERE id = ?",
            (now, req.reason, exception_id),
        )
        write_audit(
            conn,
            actor=principal.user_id,
            action="exception.revoked",
            target_type="exception",
            target_id=exception_id,
            details={"reason": req.reason},
        )
        conn.commit()
        return {"status": "revoked", "exception_id": exception_id}
    finally:
        conn.close()
