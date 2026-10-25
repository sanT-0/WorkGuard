from fastapi import APIRouter, HTTPException
import uuid, json
from app.database import get_connection, utc_now_iso
from app.crypto import sign_envelope
from app.schemas import (
    PolicySummary, PolicyDetail, CreateDraftPolicyRequest,
    EditDraftPolicyRequest, ApprovePolicyRequest, PublishPolicyRequest,
    RollbackPolicyRequest
)

router = APIRouter(prefix="/admin/policies", tags=["Admin Policies"])

@router.get("")
def list_policies():
    conn = get_connection()
    cur = conn.cursor()
    rows = cur.execute("SELECT * FROM policies ORDER BY updated_at DESC").fetchall()
    items = []
    for r in rows:
        items.append({
            "id": r["id"],
            "name": r["name"],
            "lifecycle_state": r["lifecycle_state"],
            "version": r["current_version"],
            "updated_at": r["updated_at"]
        })
    conn.close()
    return {"items": items}

@router.post("", status_code=201)
def create_draft_policy(req: CreateDraftPolicyRequest):
    policy_id = str(uuid.uuid4())
    now_iso = utc_now_iso()
    policy_dict = req.policy.model_dump()
    policy_dict["policy_id"] = policy_id
    policy_dict["policy_version"] = 1
    
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO policies (id, name, description, lifecycle_state, rollout_mode, current_version, created_by, updated_at) "
        "VALUES (?, ?, ?, 'draft', ?, 1, 'admin-1', ?)",
        (policy_id, req.name, req.policy.description, req.policy.rollout_mode, now_iso)
    )
    cur.execute(
        "INSERT INTO policy_versions (id, policy_id, version, policy_json, digest_sha256, signature_base64, key_id, published_at, published_by, reason) "
        "VALUES (?, ?, 1, ?, 'draft', 'draft', 'none', ?, 'admin-1', ?)",
        (str(uuid.uuid4()), policy_id, json.dumps(policy_dict), now_iso, req.reason)
    )
    conn.commit()
    conn.close()
    return {
        "id": policy_id,
        "name": req.name,
        "lifecycle_state": "draft",
        "version": 1,
        "updated_at": now_iso
    }

@router.get("/{policy_id}")
def get_policy(policy_id: str):
    conn = get_connection()
    cur = conn.cursor()
    p = cur.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if not p:
        conn.close()
        raise HTTPException(status_code=404, detail="Policy not found")
    
    pv = cur.execute(
        "SELECT * FROM policy_versions WHERE policy_id = ? ORDER BY version DESC LIMIT 1", (policy_id,)
    ).fetchone()
    conn.close()
    
    policy_obj = json.loads(pv["policy_json"]) if pv else {}
    return {
        "id": p["id"],
        "name": p["name"],
        "lifecycle_state": p["lifecycle_state"],
        "version": p["current_version"],
        "updated_at": p["updated_at"],
        "policy": policy_obj,
        "created_by": p["created_by"],
        "approved_by": p["approved_by"],
        "published_by": p["published_by"]
    }

@router.patch("/{policy_id}")
def edit_draft_policy(policy_id: str, req: EditDraftPolicyRequest):
    conn = get_connection()
    cur = conn.cursor()
    p = cur.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if not p:
        conn.close()
        raise HTTPException(status_code=404, detail="Policy not found")
    if p["lifecycle_state"] != "draft":
        conn.close()
        raise HTTPException(status_code=409, detail="Only draft policies can be edited")
    
    now_iso = utc_now_iso()
    name = req.name or p["name"]
    cur.execute("UPDATE policies SET name = ?, updated_at = ? WHERE id = ?", (name, now_iso, policy_id))
    
    if req.policy:
        pdict = req.policy.model_dump()
        pdict["policy_id"] = policy_id
        cur.execute(
            "UPDATE policy_versions SET policy_json = ? WHERE policy_id = ? AND version = ?",
            (json.dumps(pdict), policy_id, p["current_version"])
        )
    conn.commit()
    conn.close()
    return {"status": "updated", "policy_id": policy_id}

@router.post("/{policy_id}/submit")
def submit_policy(policy_id: str):
    conn = get_connection()
    cur = conn.cursor()
    p = cur.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if not p:
        conn.close()
        raise HTTPException(status_code=404, detail="Policy not found")
    if p["lifecycle_state"] != "draft":
        conn.close()
        raise HTTPException(status_code=409, detail=f"Cannot submit policy in state {p['lifecycle_state']}")
    
    now_iso = utc_now_iso()
    cur.execute("UPDATE policies SET lifecycle_state = 'submitted', updated_at = ? WHERE id = ?", (now_iso, policy_id))
    conn.commit()
    conn.close()
    return {"id": policy_id, "name": p["name"], "lifecycle_state": "submitted", "version": p["current_version"], "updated_at": now_iso}

@router.post("/{policy_id}/approve")
def approve_policy(policy_id: str, req: ApprovePolicyRequest):
    conn = get_connection()
    cur = conn.cursor()
    p = cur.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if not p:
        conn.close()
        raise HTTPException(status_code=404, detail="Policy not found")
    if p["lifecycle_state"] != "submitted":
        conn.close()
        raise HTTPException(status_code=409, detail="Only submitted policies can be approved")
    
    approver = "security-officer-2"
    now_iso = utc_now_iso()
    cur.execute(
        "UPDATE policies SET lifecycle_state = 'approved', approved_by = ?, updated_at = ? WHERE id = ?",
        (approver, now_iso, policy_id)
    )
    cur.execute(
        "INSERT INTO admin_audit_events (id, actor_user_id, action, target_type, target_id, details_json, created_at) "
        "VALUES (?, ?, 'policy.approve', 'policy', ?, ?, ?)",
        (str(uuid.uuid4()), approver, policy_id, f'{{"notes": "{req.approval_notes}"}}', now_iso)
    )
    conn.commit()
    conn.close()
    return {"id": policy_id, "name": p["name"], "lifecycle_state": "approved", "version": p["current_version"], "updated_at": now_iso}

@router.post("/{policy_id}/publish", status_code=202)
def publish_policy(policy_id: str, req: PublishPolicyRequest):
    conn = get_connection()
    cur = conn.cursor()
    p = cur.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if not p:
        conn.close()
        raise HTTPException(status_code=404, detail="Policy not found")
    
    pv = cur.execute(
        "SELECT * FROM policy_versions WHERE policy_id = ? ORDER BY version DESC LIMIT 1", (policy_id,)
    ).fetchone()
    policy_dict = json.loads(pv["policy_json"])
    policy_dict["policy_version"] = req.version
    
    digest_sha256, sig_b64, key_id = sign_envelope(policy_dict)
    now_iso = utc_now_iso()
    cur.execute(
        "UPDATE policy_versions SET digest_sha256 = ?, signature_base64 = ?, key_id = ?, published_at = ?, published_by = 'admin-pub', reason = ? "
        "WHERE id = ?",
        (digest_sha256, sig_b64, key_id, now_iso, req.reason, pv["id"])
    )
    cur.execute(
        "UPDATE policies SET lifecycle_state = 'published', current_version = ?, published_by = 'admin-pub', updated_at = ? WHERE id = ?",
        (req.version, now_iso, policy_id)
    )
    cur.execute("UPDATE devices SET policy_version_desired = ? WHERE status != 'revoked'", (req.version,))
    cur.execute(
        "INSERT INTO admin_audit_events (id, actor_user_id, action, target_type, target_id, details_json, created_at) "
        "VALUES (?, 'admin-pub', 'policy.publish', 'policy', ?, ?, ?)",
        (str(uuid.uuid4()), policy_id, f'{{"version": {req.version}, "digest": "{digest_sha256}"}}', now_iso)
    )
    conn.commit()
    conn.close()
    return {"status": "published", "version": req.version, "digest_sha256": digest_sha256}

@router.post("/{policy_id}/rollback", status_code=202)
def rollback_policy(policy_id: str, req: RollbackPolicyRequest):
    conn = get_connection()
    cur = conn.cursor()
    p = cur.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if not p:
        conn.close()
        raise HTTPException(status_code=404, detail="Policy not found")
    
    target_pv = cur.execute(
        "SELECT * FROM policy_versions WHERE policy_id = ? AND version = ?", (policy_id, req.target_version)
    ).fetchone()
    if not target_pv:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Target safe version {req.target_version} not found")
    
    new_version_num = (p["current_version"] or 1) + 1
    safe_policy_dict = json.loads(target_pv["policy_json"])
    safe_policy_dict["policy_version"] = new_version_num
    
    digest_sha256, sig_b64, key_id = sign_envelope(safe_policy_dict)
    now_iso = utc_now_iso()
    
    cur.execute(
        "INSERT INTO policy_versions (id, policy_id, version, policy_json, digest_sha256, signature_base64, key_id, rollback_of_version, published_at, published_by, reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'sec-admin', ?)",
        (str(uuid.uuid4()), policy_id, new_version_num, json.dumps(safe_policy_dict), digest_sha256, sig_b64, key_id, req.target_version, now_iso, req.reason)
    )
    cur.execute(
        "UPDATE policies SET lifecycle_state = 'published', current_version = ?, updated_at = ? WHERE id = ?",
        (new_version_num, now_iso, policy_id)
    )
    cur.execute("UPDATE devices SET policy_version_desired = ? WHERE status != 'revoked'", (new_version_num,))
    cur.execute(
        "INSERT INTO admin_audit_events (id, actor_user_id, action, target_type, target_id, details_json, created_at) "
        "VALUES (?, 'sec-admin', 'policy.rollback', 'policy', ?, ?, ?)",
        (str(uuid.uuid4()), policy_id, f'{{"rollback_to": {req.target_version}, "new_version": {new_version_num}, "reason": "{req.reason}"}}', now_iso)
    )
    conn.commit()
    conn.close()
    return {
        "id": policy_id,
        "name": p["name"],
        "lifecycle_state": "published",
        "version": new_version_num,
        "rollback_of_version": req.target_version,
        "updated_at": now_iso
    }
