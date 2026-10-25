from fastapi import APIRouter, Query
from typing import Optional
import json
from app.database import get_connection

router = APIRouter(prefix="/admin", tags=["Admin Events"])

@router.get("/events")
def list_events(
    cursor: Optional[str] = Query(None),
    device_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200)
):
    conn = get_connection()
    cur = conn.cursor()
    query = "SELECT * FROM security_events"
    clauses = []
    params = []
    if device_id:
        clauses.append("device_id = ?")
        params.append(device_id)
    if event_type:
        clauses.append("event_type = ?")
        params.append(event_type)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY occurred_at DESC LIMIT ?"
    params.append(limit)
    rows = cur.execute(query, params).fetchall()
    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "device_id": r["device_id"],
            "event_type": r["event_type"],
            "severity": r["severity"],
            "occurred_at": r["occurred_at"],
            "source": r["source"],
            "response_state": r["response_state"]
        })
    conn.close()
    return {"items": items, "next_cursor": None}

@router.get("/audit-events")
def list_audit_events(
    cursor: Optional[str] = Query(None),
    actor_user_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200)
):
    conn = get_connection()
    cur = conn.cursor()
    query = "SELECT * FROM admin_audit_events"
    clauses = []
    params = []
    if actor_user_id:
        clauses.append("actor_user_id = ?")
        params.append(actor_user_id)
    if action:
        clauses.append("action = ?")
        params.append(action)
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = cur.execute(query, params).fetchall()
    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "actor_user_id": r["actor_user_id"],
            "action": r["action"],
            "target_type": r["target_type"],
            "target_id": r["target_id"],
            "details": json.loads(r["details_json"]) if r["details_json"] else {},
            "created_at": r["created_at"]
        })
    conn.close()
    return {"items": items, "next_cursor": None}
