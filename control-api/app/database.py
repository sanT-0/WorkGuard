import sqlite3
import os
import json
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "workguard.db")

def utc_now_iso():
    return datetime.now(timezone.utc).isoformat()

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def init_db():
    conn = get_connection()
    cur = conn.cursor()
    cur.executescript("""
    CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY,
        display_name TEXT NOT NULL,
        assigned_user_id TEXT,
        os_version TEXT NOT NULL,
        os_edition TEXT NOT NULL DEFAULT 'Windows 11 Enterprise',
        agent_version TEXT NOT NULL DEFAULT '1.0.0',
        status TEXT NOT NULL DEFAULT 'enrolled',
        last_seen_at TEXT,
        policy_version_desired INTEGER,
        policy_version_observed INTEGER,
        device_public_key TEXT,
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
        signature_base64 TEXT NOT NULL,
        key_id TEXT NOT NULL,
        rollback_of_version INTEGER,
        published_at TEXT NOT NULL,
        published_by TEXT NOT NULL,
        reason TEXT,
        FOREIGN KEY (policy_id) REFERENCES policies(id),
        UNIQUE(policy_id, version)
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
        created_at TEXT NOT NULL
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
    """)
    conn.commit()
    conn.close()
