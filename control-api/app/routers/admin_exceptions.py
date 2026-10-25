from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
import uuid
from app.database import get_connection, utc_now_iso

router = APIRouter(prefix="/admin/exceptions", tags=["Admin Exceptions"])

class CreateExceptionRequest(BaseModel):
    device_id: str
    control_id: str
    reason: str = Field(min_length=5, max_length=500)
    expires_at: str

class RevokeExceptionRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)

@router.post("", status_code=201)
def create_exception(req: CreateExceptionRequest):
    conn = get_connection()
    cur = conn.cursor()
    dev = cur.execute("SELECT * FROM devices WHERE id = ?", (req.device_id,)).fetchone()
    if not dev:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")
    
    exc_id = str(uuid.uuid4())
    now_iso = utc_now_iso()
    cur.execute(
        "INSERT INTO policy_exceptions (id, device_id, control_id, reason, status, created_at, expires_at) "
        "VALUES (?, ?, ?, ?, 'active', ?, ?)",
        (exc_id, req.device_id, req.control_id, req.reason, now_iso, req.expires_at)
    )
    conn.commit()
    conn.close()
    return {
        "id": exc_id,
        "device_id": req.device_id,
        "control_id": req.control_id,
        "reason": req.reason,
        "status": "active",
        "created_at": now_iso,
        "expires_at": req.expires_at
    }

@router.post("/{exception_id}/revoke")
def revoke_exception(exception_id: str, req: RevokeExceptionRequest):
    conn = get_connection()
    cur = conn.cursor()
    exc = cur.execute("SELECT * FROM policy_exceptions WHERE id = ?", (exception_id,)).fetchone()
    if not exc:
        conn.close()
        raise HTTPException(status_code=404, detail="Exception not found")
    
    now_iso = utc_now_iso()
    cur.execute(
        "UPDATE policy_exceptions SET status = 'revoked', revoked_at = ?, revoked_reason = ? WHERE id = ?",
        (now_iso, req.reason, exception_id)
    )
    conn.commit()
    conn.close()
    return {"status": "revoked", "exception_id": exception_id}
