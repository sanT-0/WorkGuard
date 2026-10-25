"""Compliance derivation and fleet freshness rules."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from app import config
from app.database import get_connection, utc_now_iso
from app.validation import required_control_ids


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    except ValueError:
        return None


def is_stale(device: dict[str, Any], now: datetime | None = None) -> bool:
    last_seen = _parse(device.get("last_seen_at"))
    if last_seen is None:
        return True
    current = now or datetime.now(UTC)
    return current - last_seen > timedelta(seconds=config.DEVICE_STALE_AFTER_SECONDS)


def refresh_stale_devices(conn=None) -> int:
    """Mark devices stale after the configured heartbeat window."""

    own = conn is None
    conn = conn or get_connection()
    try:
        cutoff = (
            datetime.now(UTC)
            - timedelta(seconds=config.DEVICE_STALE_AFTER_SECONDS)
        ).isoformat()
        cursor = conn.execute(
            "UPDATE devices SET status = 'stale' "
            "WHERE status NOT IN ('revoked', 'stale') "
            "AND (last_seen_at IS NULL OR last_seen_at < ?)",
            (cutoff,),
        )
        changed = cursor.rowcount or 0
        if own:
            conn.commit()
        return changed
    finally:
        if own:
            conn.close()


def get_assigned_policy(conn, device_id: str) -> dict[str, Any] | None:
    """Return the device's assignment joined to an immutable policy version."""

    # Serve the assignment even while a newer draft is pending.  The policy
    # row leaves the `published` state when `new-draft` runs, but the currently
    # published version must remain active until the draft is published.
    row = conn.execute(
        "SELECT a.device_id, a.policy_id, a.desired_version, a.rollout_group, "
        "       p.lifecycle_state, p.name AS policy_name, "
        "       pv.id AS version_id, pv.version, pv.policy_json, pv.digest_sha256 "
        "FROM device_policy_assignments a "
        "JOIN policies p ON p.id = a.policy_id "
        "JOIN policy_versions pv "
        "  ON pv.policy_id = a.policy_id AND pv.version = a.desired_version "
        "WHERE a.device_id = ? AND p.current_version IS NOT NULL "
        "  AND a.desired_version = p.current_version",
        (device_id,),
    ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["policy"] = json.loads(result.pop("policy_json"))
    return result


def ensure_assignment(conn, device_id: str, policy_id: str | None = None) -> None:
    """Assign the newest published policy to a device if it has no assignment."""

    existing = conn.execute(
        "SELECT 1 FROM device_policy_assignments WHERE device_id = ?", (device_id,)
    ).fetchone()
    if existing:
        return

    # A pending draft does not retire the last published version, so assignment
    # is based on current_version rather than the lifecycle label.
    if policy_id:
        row = conn.execute(
            "SELECT id, current_version FROM policies "
            "WHERE id = ? AND current_version IS NOT NULL",
            (policy_id,),
        ).fetchone()
    else:
        row = conn.execute(
            "SELECT id, current_version FROM policies "
            "WHERE current_version IS NOT NULL "
            "ORDER BY updated_at DESC LIMIT 1"
        ).fetchone()
    if row is None or row["current_version"] is None:
        return

    conn.execute(
        "INSERT OR REPLACE INTO device_policy_assignments "
        "(device_id, policy_id, desired_version, rollout_group, updated_at) "
        "VALUES (?, ?, ?, 'all', ?)",
        (device_id, row["id"], row["current_version"], utc_now_iso()),
    )
    conn.execute(
        "UPDATE devices SET policy_version_desired = ? WHERE id = ?",
        (row["current_version"], device_id),
    )


def assign_policy_to_fleet(conn, policy_id: str, version: int, group: str = "all") -> int:
    rows = conn.execute(
        "SELECT id FROM devices WHERE status != 'revoked'"
    ).fetchall()
    now = utc_now_iso()
    for row in rows:
        conn.execute(
            "INSERT OR REPLACE INTO device_policy_assignments "
            "(device_id, policy_id, desired_version, rollout_group, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (row["id"], policy_id, version, group, now),
        )
        conn.execute(
            "UPDATE devices SET policy_version_desired = ? WHERE id = ?",
            (version, row["id"]),
        )
        # A newly published version is not satisfied by results for the old
        # version.  Re-derive immediately so a device cannot keep showing as
        # compliant until it happens to upload fresh read-backs.
        update_compliance(conn, row["id"])
    return len(rows)


def _latest_results(conn, device_id: str, policy_version: int) -> dict[str, dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM control_results WHERE device_id = ? AND policy_version = ?",
        (device_id, policy_version),
    ).fetchall()
    return {row["control_id"]: dict(row) for row in rows}


def active_exceptions(
    conn, device_id: str, now: datetime | None = None
) -> dict[str, dict[str, Any]]:
    """Return active, unexpired exceptions keyed by control id.

    Expiry is evaluated here rather than trusting the stored status, so an
    exception stops covering a control even if the listing sweep has not run.
    """

    current = (now or datetime.now(UTC)).isoformat()
    rows = conn.execute(
        "SELECT * FROM policy_exceptions "
        "WHERE device_id = ? AND status = 'active' AND expires_at > ?",
        (device_id, current),
    ).fetchall()
    return {row["control_id"]: dict(row) for row in rows}


def derive_compliance(
    conn, device_id: str, policy_version: int | None = None
) -> tuple[str, list[dict[str, Any]]]:
    """Derive status from required controls; never trust an agent-wide flag."""

    device = conn.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
    if device is None:
        return "unknown", []

    if device["status"] == "revoked":
        return "revoked", []

    assignment = get_assigned_policy(conn, device_id)
    if assignment is None:
        return "enrolled", []

    version = policy_version or assignment["desired_version"]
    policy = assignment["policy"]
    required = required_control_ids(policy)
    results = _latest_results(conn, device_id, version)
    exceptions = active_exceptions(conn, device_id)

    missing_or_bad = []
    for control_id in sorted(required):
        result = results.get(control_id)
        if result is not None and result["status"] == "enforced":
            continue
        exception = exceptions.get(control_id)
        if exception is not None:
            # An approved, unexpired exception satisfies the requirement for
            # compliance purposes, but the entry stays visible so the console
            # can show that coverage is exceptional rather than enforced.
            missing_or_bad.append(
                {
                    "control_id": control_id,
                    "status": "excepted",
                    "exception_id": exception["id"],
                    "expires_at": exception["expires_at"],
                }
            )
            continue
        missing_or_bad.append(
            {
                "control_id": control_id,
                "status": result["status"] if result else "unknown",
            }
        )

    if is_stale(dict(device)):
        return "stale", missing_or_bad
    if not required:
        return "compliant", []
    if any(item["status"] != "excepted" for item in missing_or_bad):
        return "noncompliant", missing_or_bad
    return "compliant", missing_or_bad


def update_compliance(conn, device_id: str, policy_version: int | None = None) -> str:
    """Recompute status, persist it, and emit a change event when it moves."""

    old = conn.execute(
        "SELECT status, policy_version_desired, policy_version_observed "
        "FROM devices WHERE id = ?",
        (device_id,),
    ).fetchone()
    status, details = derive_compliance(conn, device_id, policy_version)
    conn.execute("UPDATE devices SET status = ? WHERE id = ?", (status, device_id))

    if old is not None and old["status"] != status:
        conn.execute(
            "INSERT INTO security_events "
            "(id, device_id, event_type, severity, occurred_at, source, "
            " response_state, details_json) "
            "VALUES (?, ?, 'device.compliance_changed', ?, ?, 'control_plane', ?, ?)",
            (
                str(uuid.uuid4()),
                device_id,
                "high" if status == "noncompliant" else "info",
                utc_now_iso(),
                "alerted",
                json.dumps({"from": old["status"], "to": status, "details": details}),
            ),
        )
    return status


def restore_heartbeat(conn, device_id: str, observed_version: int | None) -> None:
    """A fresh heartbeat moves a stale device back into an evaluated state."""

    current = conn.execute(
        "SELECT status FROM devices WHERE id = ?", (device_id,)
    ).fetchone()
    if current is None:
        return
    if current["status"] == "stale":
        assignment = get_assigned_policy(conn, device_id)
        if assignment is None:
            conn.execute(
                "UPDATE devices SET status = 'enrolled' WHERE id = ?", (device_id,)
            )
        else:
            update_compliance(conn, device_id, assignment["desired_version"])
