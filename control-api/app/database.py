"""SQLite persistence for the local/MVP control plane.

The schema is written to be migration-friendly: ``init_db`` creates missing
tables and adds missing columns without destroying existing local data.
Production deployments should run the same DDL through Alembic against
PostgreSQL before the pilot gate (see ROADMAP.md).
"""

from __future__ import annotations

import base64
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app import config


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def get_connection() -> sqlite3.Connection:
    db_path = Path(config.DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA busy_timeout = 10000;")
    return conn


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    existing = {
        row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
    }
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")


def init_db() -> None:
    conn = get_connection()
    try:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL DEFAULT 'org-default',
                display_name TEXT NOT NULL,
                assigned_user_id TEXT,
                os_version TEXT NOT NULL,
                os_edition TEXT NOT NULL DEFAULT 'Windows 11 Enterprise',
                agent_version TEXT NOT NULL DEFAULT '1.0.0',
                status TEXT NOT NULL DEFAULT 'enrolled',
                last_seen_at TEXT,
                policy_version_desired INTEGER,
                policy_version_observed INTEGER,
                last_applied_version INTEGER,
                device_public_key TEXT,
                credential_hash TEXT,
                credential_issued_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS enrollment_codes (
                code_hash TEXT PRIMARY KEY,
                requested_for_user_id TEXT,
                reason TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                used_by_device_id TEXT,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policies (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL DEFAULT 'org-default',
                name TEXT NOT NULL,
                description TEXT,
                lifecycle_state TEXT NOT NULL DEFAULT 'draft',
                rollout_mode TEXT NOT NULL DEFAULT 'enforce',
                current_version INTEGER,
                created_by TEXT NOT NULL,
                approved_by TEXT,
                published_by TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policy_versions (
                id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                policy_json TEXT NOT NULL,
                digest_sha256 TEXT NOT NULL,
                signature_base64 TEXT NOT NULL DEFAULT '',
                key_id TEXT NOT NULL DEFAULT '',
                rollback_of_version INTEGER,
                published_at TEXT NOT NULL,
                published_by TEXT NOT NULL,
                reason TEXT,
                FOREIGN KEY (policy_id) REFERENCES policies(id),
                UNIQUE(policy_id, version)
            );

            CREATE TABLE IF NOT EXISTS device_policy_assignments (
                device_id TEXT PRIMARY KEY,
                policy_id TEXT NOT NULL,
                desired_version INTEGER NOT NULL,
                rollout_group TEXT NOT NULL DEFAULT 'all',
                updated_at TEXT NOT NULL,
                FOREIGN KEY (device_id) REFERENCES devices(id),
                FOREIGN KEY (policy_id) REFERENCES policies(id)
            );

            CREATE TABLE IF NOT EXISTS control_results (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                policy_version INTEGER NOT NULL,
                control_id TEXT NOT NULL,
                status TEXT NOT NULL,
                provider TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                error_code TEXT,
                safe_details TEXT,
                FOREIGN KEY (device_id) REFERENCES devices(id)
            );

            CREATE TABLE IF NOT EXISTS security_events (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                source TEXT NOT NULL,
                response_state TEXT NOT NULL,
                details_json TEXT
            );

            CREATE TABLE IF NOT EXISTS admin_audit_events (
                id TEXT PRIMARY KEY,
                actor_user_id TEXT NOT NULL,
                action TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id TEXT,
                details_json TEXT,
                created_at TEXT NOT NULL,
                prev_hash TEXT,
                record_hash TEXT
            );

            CREATE TABLE IF NOT EXISTS policy_exceptions (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                control_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT,
                revoked_reason TEXT
            );
            """
        )

        # Forward-compatible columns for databases created by the starter build.
        _ensure_column(conn, "devices", "org_id", "TEXT NOT NULL DEFAULT 'org-default'")
        _ensure_column(conn, "devices", "last_applied_version", "INTEGER")
        _ensure_column(conn, "devices", "credential_hash", "TEXT")
        _ensure_column(conn, "devices", "credential_issued_at", "TEXT")
        _ensure_column(conn, "policies", "org_id", "TEXT NOT NULL DEFAULT 'org-default'")
        _ensure_column(conn, "admin_audit_events", "prev_hash", "TEXT")
        _ensure_column(conn, "admin_audit_events", "record_hash", "TEXT")

        # Keep only the newest read-back per (device, policy version, control)
        # before creating the idempotency index.
        conn.execute(
            "DELETE FROM control_results WHERE rowid NOT IN ("
            "SELECT MAX(rowid) FROM control_results "
            "GROUP BY device_id, policy_version, control_id)"
        )

        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_devices_created
                ON devices(created_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_devices_status
                ON devices(status, last_seen_at);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_credential
                ON devices(credential_hash) WHERE credential_hash IS NOT NULL;
            CREATE INDEX IF NOT EXISTS idx_enrollment_expiry
                ON enrollment_codes(expires_at);
            CREATE INDEX IF NOT EXISTS idx_policy_versions_policy
                ON policy_versions(policy_id, version DESC);
            CREATE INDEX IF NOT EXISTS idx_assignments_policy
                ON device_policy_assignments(policy_id, desired_version);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_control_results_unique
                ON control_results(device_id, policy_version, control_id);
            CREATE INDEX IF NOT EXISTS idx_events_occurred
                ON security_events(occurred_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_events_device
                ON security_events(device_id, occurred_at DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_created
                ON admin_audit_events(created_at DESC, id DESC);
            CREATE INDEX IF NOT EXISTS idx_exceptions_device
                ON policy_exceptions(device_id, status, expires_at);
            """
        )
        conn.commit()
    finally:
        conn.close()


class InvalidCursorError(ValueError):
    """Raised when a client-supplied pagination cursor is malformed."""


def encode_cursor(created_at: str | None, row_id: str | None) -> str | None:
    if not created_at or not row_id:
        return None
    raw = json.dumps({"t": created_at, "i": row_id}, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(cursor: str | None) -> tuple[str, str] | None:
    if not cursor:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
        created_at = str(payload["t"])
        row_id = str(payload["i"])
        return created_at, row_id
    except Exception as exc:  # noqa: BLE001
        raise InvalidCursorError("Invalid pagination cursor") from exc


def apply_cursor(
    query: str,
    params: list[Any],
    cursor: str | None,
    *,
    time_column: str = "created_at",
    id_column: str = "id",
) -> tuple[str, list[Any]]:
    """Append a stable keyset-pagination predicate to a query."""

    decoded = decode_cursor(cursor)
    if decoded is None:
        return query, params
    created_at, row_id = decoded
    query += (
        f" AND ({time_column} < ? OR ({time_column} = ? AND {id_column} < ?))"
    )
    params.extend([created_at, created_at, row_id])
    return query, params
