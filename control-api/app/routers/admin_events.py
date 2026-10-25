from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.audit import decode_details, verify_audit_chain
from app.database import decode_cursor, encode_cursor, get_connection
from app.security import Principal, require_role

router = APIRouter(prefix="/admin", tags=["Admin Events"])


@router.get("/events")
def list_events(
    cursor: str | None = Query(None),
    device_id: str | None = Query(None),
    event_type: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    principal: Annotated[Principal, Depends(require_role("auditor"))] = None,
):
    conn = get_connection()
    try:
        query = "SELECT * FROM security_events WHERE 1=1"
        params: list = []
        if device_id:
            query += " AND device_id = ?"
            params.append(device_id)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        decoded = decode_cursor(cursor)
        if decoded:
            occurred_at, row_id = decoded
            query += " AND (occurred_at < ? OR (occurred_at = ? AND id < ?))"
            params.extend([occurred_at, occurred_at, row_id])
        query += " ORDER BY occurred_at DESC, id DESC LIMIT ?"
        params.append(limit + 1)
        rows = conn.execute(query, params).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = []
        for row in rows:
            item = {
                "id": row["id"],
                "device_id": row["device_id"],
                "event_type": row["event_type"],
                "severity": row["severity"],
                "occurred_at": row["occurred_at"],
                "source": row["source"],
                "response_state": row["response_state"],
            }
            if row["details_json"]:
                item["details"] = decode_details(row["details_json"])
            items.append(item)
        next_cursor = None
        if has_more and rows:
            next_cursor = encode_cursor(rows[-1]["occurred_at"], rows[-1]["id"])
        return {"items": items, "next_cursor": next_cursor}
    finally:
        conn.close()


@router.get("/audit-events")
def list_audit_events(
    cursor: str | None = Query(None),
    actor_user_id: str | None = Query(None),
    action: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    principal: Annotated[Principal, Depends(require_role("auditor"))] = None,
):
    conn = get_connection()
    try:
        query = "SELECT * FROM admin_audit_events WHERE 1=1"
        params: list = []
        if actor_user_id:
            query += " AND actor_user_id = ?"
            params.append(actor_user_id)
        if action:
            query += " AND action = ?"
            params.append(action)
        decoded = decode_cursor(cursor)
        if decoded:
            created_at, row_id = decoded
            query += " AND (created_at < ? OR (created_at = ? AND id < ?))"
            params.extend([created_at, created_at, row_id])
        query += " ORDER BY created_at DESC, id DESC LIMIT ?"
        params.append(limit + 1)
        rows = conn.execute(query, params).fetchall()
        has_more = len(rows) > limit
        rows = rows[:limit]
        items = []
        for row in rows:
            items.append(
                {
                    "id": row["id"],
                    "actor_user_id": row["actor_user_id"],
                    "action": row["action"],
                    "target_type": row["target_type"],
                    "target_id": row["target_id"],
                    "details": decode_details(row["details_json"]),
                    "created_at": row["created_at"],
                    "prev_hash": row["prev_hash"],
                    "record_hash": row["record_hash"],
                }
            )
        next_cursor = None
        if has_more and rows:
            next_cursor = encode_cursor(rows[-1]["created_at"], rows[-1]["id"])
        return {"items": items, "next_cursor": next_cursor}
    finally:
        conn.close()


@router.get("/audit-events/verify")
def verify_audit(
    principal: Annotated[Principal, Depends(require_role("auditor"))] = None,
):
    conn = get_connection()
    try:
        return verify_audit_chain(conn)
    finally:
        conn.close()
