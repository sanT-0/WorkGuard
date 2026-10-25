import os, json, uuid
from datetime import datetime, timezone, timedelta
from app.database import get_connection, init_db, utc_now_iso
from app.crypto import sign_envelope

def seed():
    init_db()
    conn = get_connection()
    cur = conn.cursor()
    
    existing = cur.execute("SELECT COUNT(*) as cnt FROM policies").fetchone()["cnt"]
    if existing > 0:
        conn.close()
        return
    
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    
    pol_id = "00000000-0000-4000-8000-000000000001"
    policy_content = {
        "schema_version": "1.0.0",
        "policy_id": pol_id,
        "policy_version": 1,
        "name": "Standard Remote Developer Baseline",
        "description": "Baseline policy enforcing USB removable storage block, BitLocker AES-256 disk encryption, App Control, and Endpoint Protection.",
        "rollout_mode": "enforce",
        "controls": [
            {
                "control_id": "removable_storage",
                "required": True,
                "settings": {
                    "action": "deny",
                    "device_classes": ["USB_MSD", "CD_DVD"],
                    "audit_only": False
                }
            },
            {
                "control_id": "disk_encryption",
                "required": True,
                "settings": {
                    "require_bitlocker": True,
                    "min_cipher_strength": "aes_256",
                    "require_tpm": True
                }
            },
            {
                "control_id": "application_control",
                "required": True,
                "settings": {
                    "mode": "enforce",
                    "allowed_publishers": ["Microsoft Corporation", "Google LLC", "Git for Windows"],
                    "allowed_paths": ["C:\\Program Files\\*", "C:\\Program Files (x86)\\*"]
                }
            },
            {
                "control_id": "endpoint_protection",
                "required": True,
                "settings": {
                    "require_antivirus": True,
                    "require_realtime_protection": True,
                    "max_signature_age_days": 3
                }
            },
            {
                "control_id": "network_policy",
                "required": True,
                "settings": {
                    "require_firewall": True,
                    "block_inbound": True,
                    "authorized_git_remotes": ["github.com/company-org/*"]
                }
            }
        ]
    }
    digest_sha256, sig_b64, key_id = sign_envelope(policy_content)
    
    cur.execute(
        "INSERT INTO policies (id, name, description, lifecycle_state, rollout_mode, current_version, created_by, approved_by, published_by, updated_at) "
        "VALUES (?, ?, ?, 'published', 'enforce', 1, 'admin-sec1', 'approver-sec2', 'publisher-sec3', ?)",
        (pol_id, policy_content["name"], policy_content["description"], now_iso)
    )
    cur.execute(
        "INSERT INTO policy_versions (id, policy_id, version, policy_json, digest_sha256, signature_base64, key_id, published_at, published_by, reason) "
        "VALUES (?, ?, 1, ?, ?, ?, ?, ?, 'publisher-sec3', 'Initial company baseline rollout')",
        (str(uuid.uuid4()), pol_id, json.dumps(policy_content), digest_sha256, sig_b64, key_id, now_iso)
    )
    
    devices_data = [
        ("dev-sim-001", "WIN11-ENG-01", "Windows 11 Enterprise (23H2)", "Windows 11 Enterprise", "compliant", 0, 1, 1),
        ("dev-sim-002", "WIN11-ENG-02", "Windows 11 Enterprise (23H2)", "Windows 11 Enterprise", "compliant", 4, 1, 1),
        ("dev-sim-003", "WIN11-PRO-03", "Windows 11 Pro (23H2)", "Windows 11 Pro", "compliant", 2, 1, 1),
        ("dev-sim-004", "WIN11-OFF-04", "Windows 11 Enterprise (22H2)", "Windows 11 Enterprise", "stale", 45, 1, 1),
    ]
    for did, dname, os_ver, os_ed, status, mins_ago, des_v, obs_v in devices_data:
        seen = (now - timedelta(minutes=mins_ago)).isoformat()
        cur.execute(
            "INSERT INTO devices (id, display_name, assigned_user_id, os_version, os_edition, agent_version, status, last_seen_at, policy_version_desired, policy_version_observed, created_at) "
            "VALUES (?, ?, ?, ?, ?, '1.0.0', ?, ?, ?, ?, ?)",
            (did, dname, str(uuid.uuid4()), os_ver, os_ed, status, seen, des_v, obs_v, now_iso)
        )
        c_status = "unsupported" if os_ed == "Windows 11 Pro" else "enforced"
        controls = [
            ("removable_storage", "enforced", "Windows Defender Removable Storage Filter"),
            ("disk_encryption", "enforced", "BitLocker CSP AES-256-XTS"),
            ("application_control", c_status, "AppLocker / App Control for Business"),
            ("endpoint_protection", "enforced", "Microsoft Defender Antivirus 4.18.24080.9"),
            ("network_policy", "enforced", "Windows Advanced Firewall")
        ]
        for cid, st, prov in controls:
            cur.execute(
                "INSERT INTO control_results (id, device_id, policy_version, control_id, status, provider, observed_at, error_code, safe_details) "
                "VALUES (?, ?, 1, ?, ?, ?, ?, NULL, 'Policy applied and verified by agent')",
                (str(uuid.uuid4()), did, cid, st, prov, seen)
            )
            
    events_data = [
        ("dev-sim-001", "usb.device.blocked", "high", 15, "removable_storage", "blocked"),
        ("dev-sim-002", "disk.bitlocker.verified", "info", 60, "disk_encryption", "verified"),
        ("dev-sim-003", "appcontrol.unsupported", "medium", 120, "application_control", "logged"),
        ("dev-sim-004", "agent.tamper.detected", "critical", 180, "service_manager", "alerted")
    ]
    for did, etype, sev, mins_ago, src, resp in events_data:
        ev_time = (now - timedelta(minutes=mins_ago)).isoformat()
        cur.execute(
            "INSERT INTO security_events (id, device_id, event_type, severity, occurred_at, source, response_state) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), did, etype, sev, ev_time, src, resp)
        )
        
    audit_data = [
        ("admin-sec1", "policy.publish", "policy", pol_id, {"version": 1, "digest": digest_sha256}, 240),
        ("approver-sec2", "policy.approve", "policy", pol_id, {"two_person_rule": "approved"}, 300),
        ("sec-admin", "device.enroll", "device", "dev-sim-001", {"display_name": "WIN11-ENG-01"}, 600)
    ]
    for act, action, ttype, tid, det_dict, mins_ago in audit_data:
        atime = (now - timedelta(minutes=mins_ago)).isoformat()
        cur.execute(
            "INSERT INTO admin_audit_events (id, actor_user_id, action, target_type, target_id, details_json, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), act, action, ttype, tid, json.dumps(det_dict), atime)
        )
        
    conn.commit()
    conn.close()

if __name__ == "__main__":
    seed()
