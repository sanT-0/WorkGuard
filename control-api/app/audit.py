"""Append-oriented, hash-chained administrator audit records."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Iterable
from typing import Any

from app.database import utc_now_iso

GENESIS_HASH = "0" * 64


def serialize_details(details: Any) -> str:
    return json.dumps(details or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _record_hash(
    prev_hash: str,
    actor: str,
    action: str,
    target_type: str,
    target_id: str | None,
    details_json: str,
    created_at: str,
) -> str:
    material = "\n".join(
        [
            prev_hash,
            actor,
            action,
            target_type,
            target_id or "",
            details_json,
            created_at,
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _last_hash(conn) -> str:
    row = conn.execute(
        "SELECT record_hash FROM admin_audit_events "
        "WHERE record_hash IS NOT NULL AND record_hash != '' "
        "ORDER BY rowid DESC LIMIT 1"
    ).fetchone()
    return row["record_hash"] if row else GENESIS_HASH


def write_audit(
    conn,
    *,
    actor: str,
    action: str,
    target_type: str,
    target_id: str | None = None,
    details: Any = None,
    created_at: str | None = None,
) -> str:
    """Insert an audit row and return its id.  The caller owns the transaction."""

    created = created_at or utc_now_iso()
    details_json = serialize_details(details)
    prev_hash = _last_hash(conn)
    record_hash = _record_hash(
        prev_hash, actor, action, target_type, target_id, details_json, created
    )
    audit_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO admin_audit_events "
        "(id, actor_user_id, action, target_type, target_id, details_json, "
        " created_at, prev_hash, record_hash) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            audit_id,
            actor,
            action,
            target_type,
            target_id,
            details_json,
            created,
            prev_hash,
            record_hash,
        ),
    )
    return audit_id


def verify_audit_chain(conn) -> dict[str, Any]:
    rows: Iterable = conn.execute(
        "SELECT rowid, id, actor_user_id, action, target_type, target_id, "
        "details_json, created_at, prev_hash, record_hash "
        "FROM admin_audit_events WHERE record_hash IS NOT NULL AND record_hash != '' "
        "ORDER BY rowid ASC"
    ).fetchall()

    expected_prev = GENESIS_HASH
    checked = 0
    for row in rows:
        if row["prev_hash"] != expected_prev:
            return {
                "valid": False,
                "checked": checked,
                "broken_id": row["id"],
                "reason": "previous hash does not match the chain",
            }
        computed = _record_hash(
            row["prev_hash"],
            row["actor_user_id"],
            row["action"],
            row["target_type"],
            row["target_id"],
            row["details_json"],
            row["created_at"],
        )
        if computed != row["record_hash"]:
            return {
                "valid": False,
                "checked": checked,
                "broken_id": row["id"],
                "reason": "record hash does not match its content",
            }
        expected_prev = row["record_hash"]
        checked += 1

    return {"valid": True, "checked": checked, "head": expected_prev}


def decode_details(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {"value": parsed}
    except json.JSONDecodeError:
        # Legacy rows used f-string JSON.  Do not let a malformed historical
        # record break the audit listing.
        return {"_unparsed": value}
