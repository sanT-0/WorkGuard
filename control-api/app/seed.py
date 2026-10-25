"""Idempotent local seed data and developer device credentials."""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta

from app import config
from app.audit import write_audit
from app.database import get_connection, init_db, utc_now_iso
from app.policy_verify import policy_digest
from app.security import generate_device_token, hash_device_token
from app.validation import validate_policy

DEMO_POLICY_ID = "00000000-0000-4000-8000-000000000001"


def _demo_policy() -> dict:
    return {
        "schema_version": "1.0.0",
        "policy_id": DEMO_POLICY_ID,
        "policy_version": 1,
        "name": "Standard Remote Developer Baseline",
        "description": (
            "Baseline enforcing USB removable-storage block, BitLocker AES-256, "
            "application control, endpoint protection and host firewall."
        ),
        "rollout_mode": "enforce",
        "controls": [
            {
                "control_id": "removable_storage",
                "required": True,
                "settings": {
                    "action": "deny",
                    "device_classes": ["USB_MSD", "CD_DVD"],
                    "audit_only": False,
                },
            },
            {
                "control_id": "disk_encryption",
                "required": True,
                "settings": {
                    "require_bitlocker": True,
                    "min_cipher_strength": "aes_256",
                    "require_tpm": True,
                },
            },
            {
                "control_id": "application_control",
                "required": True,
                "settings": {
                    "mode": "enforce",
                    "allowed_publishers": [
                        "Microsoft Corporation",
                        "Google LLC",
                        "Git for Windows",
                    ],
                    "allowed_paths": [
                        "C:\\Program Files\\*",
                        "C:\\Program Files (x86)\\*",
                    ],
                },
            },
            {
                "control_id": "endpoint_protection",
                "required": True,
                "settings": {
                    "require_antivirus": True,
                    "require_realtime_protection": True,
                    "max_signature_age_days": 3,
                },
            },
            {
                "control_id": "network_policy",
                "required": True,
                "settings": {
                    "require_firewall": True,
                    "block_inbound": True,
                    "authorized_git_remotes": ["github.com/company-org/*"],
                },
            },
        ],
    }


def _seed_policy_if_missing(conn) -> None:
    existing = conn.execute("SELECT COUNT(*) AS cnt FROM policies").fetchone()["cnt"]
    if existing:
        return

    policy = _demo_policy()
    validate_policy(policy)
    now = utc_now_iso()
    conn.execute(
        "INSERT INTO policies "
        "(id, org_id, name, description, lifecycle_state, rollout_mode, "
        " current_version, created_by, approved_by, published_by, updated_at) "
        "VALUES (?, 'org-default', ?, ?, 'published', ?, 1, "
        "        'seed-author', 'seed-approver', 'seed-publisher', ?)",
        (policy["policy_id"], policy["name"], policy["description"], policy["rollout_mode"], now),
    )
    conn.execute(
        "INSERT INTO policy_versions "
        "(id, policy_id, version, policy_json, digest_sha256, signature_base64, "
        " key_id, published_at, published_by, reason) "
        "VALUES (?, ?, 1, ?, ?, '', ?, ?, 'seed-publisher', "
        "        'Initial company baseline rollout')",
        (
            str(uuid.uuid4()),
            policy["policy_id"],
            json.dumps(policy, sort_keys=True),
            policy_digest(policy),
            config.SIGNING_KEY_ID,
            now,
        ),
    )
    write_audit(
        conn,
        actor="seed-publisher",
        action="policy.published",
        target_type="policy",
        target_id=policy["policy_id"],
        details={"version": 1, "digest": policy_digest(policy)},
    )


def _seed_devices_if_missing(conn) -> None:
    existing = conn.execute("SELECT COUNT(*) AS cnt FROM devices").fetchone()["cnt"]
    if existing:
        return

    now = datetime.now(UTC)
    devices = [
        ("dev-sim-001", "WIN11-ENG-01", "Windows 11 Enterprise (23H2)", "Windows 11 Enterprise", "compliant", 0),
        ("dev-sim-002", "WIN11-ENG-02", "Windows 11 Enterprise (23H2)", "Windows 11 Enterprise", "compliant", 4),
        ("dev-sim-003", "WIN11-PRO-03", "Windows 11 Pro (23H2)", "Windows 11 Pro", "noncompliant", 2),
        ("dev-sim-004", "WIN11-OFF-04", "Windows 11 Enterprise (22H2)", "Windows 11 Enterprise", "stale", 45),
    ]
    for device_id, name, os_version, os_edition, status, minutes_ago in devices:
        seen = (now - timedelta(minutes=minutes_ago)).isoformat()
        conn.execute(
            "INSERT INTO devices "
            "(id, org_id, display_name, assigned_user_id, os_version, os_edition, "
            " agent_version, status, last_seen_at, policy_version_desired, "
            " policy_version_observed, last_applied_version, created_at) "
            "VALUES (?, 'org-default', ?, ?, ?, ?, '1.0.0', ?, ?, 1, 1, 1, ?)",
            (
                device_id,
                name,
                str(uuid.uuid4()),
                os_version,
                os_edition,
                status,
                seen,
                (now - timedelta(days=30)).isoformat(),
            ),
        )
        conn.execute(
            "INSERT OR REPLACE INTO device_policy_assignments "
            "(device_id, policy_id, desired_version, rollout_group, updated_at) "
            "VALUES (?, ?, 1, 'all', ?)",
            (device_id, DEMO_POLICY_ID, utc_now_iso()),
        )

        app_control_status = "unsupported" if os_edition == "Windows 11 Pro" else "enforced"
        controls = [
            ("removable_storage", "enforced", "Windows Defender Removable Storage Filter"),
            ("disk_encryption", "enforced", "BitLocker CSP AES-256-XTS"),
            ("application_control", app_control_status, "AppLocker / App Control for Business"),
            ("endpoint_protection", "enforced", "Microsoft Defender Antivirus"),
            ("network_policy", "enforced", "Windows Advanced Firewall"),
        ]
        for control_id, control_status, provider in controls:
            conn.execute(
                "INSERT OR REPLACE INTO control_results "
                "(id, device_id, policy_version, control_id, status, provider, "
                " observed_at, error_code, safe_details) "
                "VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    device_id,
                    control_id,
                    control_status,
                    provider,
                    seen,
                    None if control_status == "enforced" else "EDITION_UNSUPPORTED",
                    "Policy applied and verified by the endpoint simulator",
                ),
            )

    events = [
        ("dev-sim-001", "usb.device.blocked", "high", 15, "removable_storage", "blocked"),
        ("dev-sim-002", "disk.bitlocker.verified", "info", 60, "disk_encryption", "verified"),
        ("dev-sim-003", "appcontrol.unsupported", "medium", 120, "application_control", "logged"),
        ("dev-sim-004", "agent.tamper.detected", "critical", 180, "service_manager", "alerted"),
    ]
    for device_id, event_type, severity, minutes_ago, source, response in events:
        occurred = (now - timedelta(minutes=minutes_ago)).isoformat()
        conn.execute(
            "INSERT INTO security_events "
            "(id, device_id, event_type, severity, occurred_at, source, response_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), device_id, event_type, severity, occurred, source, response),
        )


def _normalize_policy_metadata(conn) -> None:
    """Repair digest/key metadata for rows created by the starter build."""

    rows = conn.execute("SELECT id, policy_json, digest_sha256, key_id FROM policy_versions").fetchall()
    for row in rows:
        try:
            policy = json.loads(row["policy_json"])
        except (TypeError, json.JSONDecodeError):
            continue
        digest = policy_digest(policy)
        key_id = row["key_id"] or config.SIGNING_KEY_ID
        if row["digest_sha256"] != digest or row["key_id"] != key_id:
            conn.execute(
                "UPDATE policy_versions SET digest_sha256 = ?, key_id = ? WHERE id = ?",
                (digest, key_id, row["id"]),
            )


def _load_token_file() -> dict[str, str]:
    path = config.DEVICE_TOKEN_FILE
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {str(key): str(value) for key, value in data.items()}
    except Exception:  # noqa: BLE001 - a corrupt dev file is regenerated
        return {}


def _write_token_file(tokens: dict[str, str]) -> None:
    path = config.DEVICE_TOKEN_FILE
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(tokens, indent=2, sort_keys=True), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def ensure_device_credentials(conn) -> dict[str, str]:
    """Ensure every device has a credential and a local simulator token file.

    The token file is a local development convenience only.  It is git-ignored
    and must never be copied to a deployed control plane.
    """

    tokens = _load_token_file()
    rows = conn.execute(
        "SELECT id, credential_hash FROM devices WHERE status != 'revoked'"
    ).fetchall()
    changed = False
    for row in rows:
        device_id = row["id"]
        token = tokens.get(device_id)
        if token and row["credential_hash"] == hash_device_token(token):
            continue
        token = generate_device_token()
        tokens[device_id] = token
        conn.execute(
            "UPDATE devices SET credential_hash = ?, credential_issued_at = ? "
            "WHERE id = ?",
            (hash_device_token(token), utc_now_iso(), device_id),
        )
        changed = True
    if changed or not config.DEVICE_TOKEN_FILE.exists():
        _write_token_file(tokens)
    return tokens


def seed() -> None:
    """Initialise the schema and, only in local development, demo data.

    A deployed control plane must start empty: seeding demo devices or writing
    a plaintext simulator token file outside local development would create
    unmanaged identities and expose credentials.
    """

    init_db()
    conn = get_connection()
    try:
        if config.APP_ENV == "local":
            _seed_policy_if_missing(conn)
            _seed_devices_if_missing(conn)
        _normalize_policy_metadata(conn)
        conn.execute(
            "UPDATE devices SET policy_version_desired = "
            "(SELECT current_version FROM policies WHERE current_version IS NOT NULL "
            " ORDER BY updated_at DESC LIMIT 1) "
            "WHERE policy_version_desired IS NULL"
        )
        if config.APP_ENV == "local":
            ensure_device_credentials(conn)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    seed()
