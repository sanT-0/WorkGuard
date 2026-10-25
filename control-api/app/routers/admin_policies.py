from __future__ import annotations

import json
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from app import config
from app.audit import write_audit
from app.compliance import assign_policy_to_fleet
from app.database import get_connection, utc_now_iso
from app.policy_verify import policy_digest
from app.schemas import (
    ApprovePolicyRequest,
    CreateDraftPolicyRequest,
    EditDraftPolicyRequest,
    PolicyDetail,
    PolicyObject,
    PolicySummary,
    PolicyVersionSummary,
    PublishPolicyRequest,
    RollbackPolicyRequest,
)
from app.security import Principal, require_role
from app.validation import validate_policy

router = APIRouter(prefix="/admin/policies", tags=["Admin Policies"])


def _summary(row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "lifecycle_state": row["lifecycle_state"],
        "version": row["current_version"],
        "updated_at": row["updated_at"],
        "created_by": row["created_by"],
        "approved_by": row["approved_by"],
        "published_by": row["published_by"],
    }


def _latest_version_row(conn, policy_id: str):
    return conn.execute(
        "SELECT * FROM policy_versions WHERE policy_id = ? "
        "ORDER BY version DESC LIMIT 1",
        (policy_id,),
    ).fetchone()


def _version_summary(row) -> dict:
    return {
        "version": row["version"],
        "digest_sha256": row["digest_sha256"],
        "key_id": row["key_id"],
        "rollback_of_version": row["rollback_of_version"],
        "published_at": row["published_at"],
        "published_by": row["published_by"],
        "reason": row["reason"],
    }


def _insert_version(
    conn,
    *,
    policy: dict,
    actor: str,
    reason: str,
    rollback_of: int | None = None,
) -> None:
    validate_policy(policy)
    digest = policy_digest(policy)
    conn.execute(
        "INSERT INTO policy_versions "
        "(id, policy_id, version, policy_json, digest_sha256, signature_base64, "
        " key_id, rollback_of_version, published_at, published_by, reason) "
        "VALUES (?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?)",
        (
            str(uuid.uuid4()),
            policy["policy_id"],
            policy["policy_version"],
            json.dumps(policy, sort_keys=True, separators=(",", ":")),
            digest,
            # The signature is applied to the short-lived, device-targeted
            # envelope at fetch time; the stored version is immutable content.
            "pending-envelope-signature",
            rollback_of,
            utc_now_iso(),
            actor,
            reason,
        ),
    )


def _require_row(conn, policy_id: str):
    row = conn.execute("SELECT * FROM policies WHERE id = ?", (policy_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Policy not found")
    return row


@router.get("")
def list_policies(
    principal: Annotated[Principal, Depends(require_role("auditor"))] = None,
):
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM policies ORDER BY updated_at DESC"
        ).fetchall()
        return {"items": [_summary(row) for row in rows]}
    finally:
        conn.close()


@router.post("", response_model=PolicySummary, status_code=201)
def create_draft_policy(
    req: CreateDraftPolicyRequest,
    principal: Annotated[Principal, Depends(require_role("security_admin"))] = None,
):
    policy_id = str(uuid.uuid4())
    policy = req.policy.model_dump()
    policy["policy_id"] = policy_id
    policy["policy_version"] = 1
    policy["name"] = req.name
    policy["description"] = req.policy.description or ""
    validate_policy(policy)

    now = utc_now_iso()
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO policies "
            "(id, org_id, name, description, lifecycle_state, rollout_mode, "
            " current_version, created_by, updated_at) "
            "VALUES (?, 'org-default', ?, ?, 'draft', ?, NULL, ?, ?)",
            (
                policy_id,
                req.name,
                policy["description"],
                policy["rollout_mode"],
                principal.user_id,
                now,
            ),
        )
        _insert_version(
            conn, policy=policy, actor=principal.user_id, reason=req.reason
        )
        write_audit(
            conn,
            actor=principal.user_id,
            action="policy.created",
            target_type="policy",
            target_id=policy_id,
            details={"version": 1, "reason": req.reason},
        )
        conn.commit()
        return _summary(_require_row(conn, policy_id))
    finally:
        conn.close()


@router.get("/{policy_id}", response_model=PolicyDetail)
def get_policy(
    policy_id: str,
    principal: Annotated[Principal, Depends(require_role("auditor"))] = None,
):
    conn = get_connection()
    try:
        row = _require_row(conn, policy_id)
        latest = _latest_version_row(conn, policy_id)
        if latest is None:
            raise HTTPException(status_code=404, detail="Policy has no version")
        policy = json.loads(latest["policy_json"])
        versions = conn.execute(
            "SELECT * FROM policy_versions WHERE policy_id = ? ORDER BY version DESC",
            (policy_id,),
        ).fetchall()
        payload = _summary(row)
        payload.update(
            {
                "policy": PolicyObject.model_validate(policy).model_dump(),
                "versions": [_version_summary(item) for item in versions],
            }
        )
        return payload
    finally:
        conn.close()


@router.get("/{policy_id}/versions", response_model=list[PolicyVersionSummary])
def get_policy_versions(
    policy_id: str,
    principal: Annotated[Principal, Depends(require_role("auditor"))] = None,
):
    conn = get_connection()
    try:
        _require_row(conn, policy_id)
        rows = conn.execute(
            "SELECT * FROM policy_versions WHERE policy_id = ? ORDER BY version DESC",
            (policy_id,),
        ).fetchall()
        return [_version_summary(row) for row in rows]
    finally:
        conn.close()


@router.patch("/{policy_id}")
def edit_draft_policy(
    policy_id: str,
    req: EditDraftPolicyRequest,
    principal: Annotated[Principal, Depends(require_role("security_admin"))] = None,
):
    conn = get_connection()
    try:
        row = _require_row(conn, policy_id)
        if row["lifecycle_state"] != "draft":
            raise HTTPException(status_code=409, detail="Only draft policies can be edited")

        latest = _latest_version_row(conn, policy_id)
        if latest is None:
            raise HTTPException(status_code=409, detail="Draft has no version")
        policy = json.loads(latest["policy_json"])

        draft_version = int(latest["version"])
        if req.policy is not None:
            policy = req.policy.model_dump()
            policy["policy_id"] = policy_id
            policy["policy_version"] = draft_version
        if req.name is not None:
            policy["name"] = req.name
        validate_policy(policy)

        now = utc_now_iso()
        conn.execute(
            "UPDATE policies SET name = ?, description = ?, rollout_mode = ?, "
            "updated_at = ? WHERE id = ?",
            (
                policy["name"],
                policy.get("description", ""),
                policy.get("rollout_mode", "enforce"),
                now,
                policy_id,
            ),
        )
        conn.execute(
            "UPDATE policy_versions SET policy_json = ?, digest_sha256 = ? "
            "WHERE policy_id = ? AND version = ?",
            (
                json.dumps(policy, sort_keys=True, separators=(",", ":")),
                policy_digest(policy),
                policy_id,
                policy["policy_version"],
            ),
        )
        write_audit(
            conn,
            actor=principal.user_id,
            action="policy.edited",
            target_type="policy",
            target_id=policy_id,
            details={"version": policy["policy_version"], "reason": req.reason or "Draft updated"},
        )
        conn.commit()
        return {"status": "updated", "policy_id": policy_id, "version": policy["policy_version"]}
    finally:
        conn.close()


@router.post("/{policy_id}/new-draft", status_code=201)
def new_draft_from_published(
    policy_id: str,
    principal: Annotated[Principal, Depends(require_role("security_admin"))] = None,
):
    """Clone the currently published version into a new editable draft."""

    conn = get_connection()
    try:
        row = _require_row(conn, policy_id)
        if row["current_version"] is None:
            raise HTTPException(status_code=409, detail="Policy has no published version")
        latest = _latest_version_row(conn, policy_id)
        if latest and int(latest["version"]) > int(row["current_version"]):
            raise HTTPException(status_code=409, detail="A draft already exists")

        published = conn.execute(
            "SELECT * FROM policy_versions WHERE policy_id = ? AND version = ?",
            (policy_id, row["current_version"]),
        ).fetchone()
        if published is None:
            raise HTTPException(status_code=409, detail="Published version is missing")

        policy = json.loads(published["policy_json"])
        draft_version = int(row["current_version"]) + 1
        policy["policy_version"] = draft_version
        policy["name"] = row["name"]
        _insert_version(
            conn,
            policy=policy,
            actor=principal.user_id,
            reason="Draft created from published version",
        )
        now = utc_now_iso()
        conn.execute(
            # Keep published_by: it still describes the version devices are
            # running.  Only the approval for the new draft is cleared.
            "UPDATE policies SET lifecycle_state = 'draft', approved_by = NULL, "
            "updated_at = ? WHERE id = ?",
            (now, policy_id),
        )
        write_audit(
            conn,
            actor=principal.user_id,
            action="policy.draft_created",
            target_type="policy",
            target_id=policy_id,
            details={
                "from_version": row["current_version"],
                "draft_version": draft_version,
            },
        )
        conn.commit()
        payload = _summary(_require_row(conn, policy_id))
        payload["draft_version"] = draft_version
        return payload
    finally:
        conn.close()


@router.post("/{policy_id}/submit")
def submit_policy(
    policy_id: str,
    principal: Annotated[Principal, Depends(require_role("security_admin"))] = None,
):
    conn = get_connection()
    try:
        row = _require_row(conn, policy_id)
        if row["lifecycle_state"] != "draft":
            raise HTTPException(
                status_code=409,
                detail=f"Cannot submit policy in state {row['lifecycle_state']}",
            )
        now = utc_now_iso()
        conn.execute(
            "UPDATE policies SET lifecycle_state = 'submitted', updated_at = ? "
            "WHERE id = ?",
            (now, policy_id),
        )
        latest = _latest_version_row(conn, policy_id)
        write_audit(
            conn,
            actor=principal.user_id,
            action="policy.submitted",
            target_type="policy",
            target_id=policy_id,
            details={"version": latest["version"] if latest else None},
        )
        conn.commit()
        updated = _require_row(conn, policy_id)
        return _summary(updated)
    finally:
        conn.close()


@router.post("/{policy_id}/approve")
def approve_policy(
    policy_id: str,
    req: ApprovePolicyRequest,
    principal: Annotated[Principal, Depends(require_role("security_admin"))] = None,
):
    conn = get_connection()
    try:
        row = _require_row(conn, policy_id)
        if row["lifecycle_state"] != "submitted":
            raise HTTPException(status_code=409, detail="Only submitted policies can be approved")
        if row["created_by"] == principal.user_id:
            raise HTTPException(
                status_code=403,
                detail="Policy author cannot approve their own policy",
            )
        now = utc_now_iso()
        conn.execute(
            "UPDATE policies SET lifecycle_state = 'approved', approved_by = ?, "
            "updated_at = ? WHERE id = ?",
            (principal.user_id, now, policy_id),
        )
        latest = _latest_version_row(conn, policy_id)
        write_audit(
            conn,
            actor=principal.user_id,
            action="policy.approved",
            target_type="policy",
            target_id=policy_id,
            details={
                "version": latest["version"] if latest else None,
                "notes": req.approval_notes,
                "author": row["created_by"],
            },
        )
        conn.commit()
        return _summary(_require_row(conn, policy_id))
    finally:
        conn.close()


@router.post("/{policy_id}/publish", status_code=202)
def publish_policy(
    policy_id: str,
    req: PublishPolicyRequest,
    principal: Annotated[Principal, Depends(require_role("security_admin"))] = None,
):
    conn = get_connection()
    try:
        row = _require_row(conn, policy_id)
        if row["lifecycle_state"] != "approved":
            raise HTTPException(
                status_code=409,
                detail="Policy must be approved before publishing",
            )
        if row["created_by"] == principal.user_id:
            raise HTTPException(
                status_code=403,
                detail="Policy author cannot publish their own policy",
            )
        if row["approved_by"] is None:
            raise HTTPException(status_code=409, detail="Policy has no approver")

        latest = _latest_version_row(conn, policy_id)
        if latest is None:
            raise HTTPException(status_code=409, detail="Policy has no version")
        publish_version = int(latest["version"])
        published_version = int(row["current_version"] or 0)
        if publish_version <= published_version:
            raise HTTPException(
                status_code=409,
                detail="No new draft version is ready to publish",
            )
        if req.version is not None and req.version != publish_version:
            raise HTTPException(
                status_code=409,
                detail=f"Expected version {publish_version}, got {req.version}",
            )

        policy = json.loads(latest["policy_json"])
        policy["policy_version"] = publish_version
        policy["name"] = row["name"]
        validate_policy(policy)
        now = utc_now_iso()
        digest = policy_digest(policy)
        conn.execute(
            "UPDATE policy_versions SET policy_json = ?, digest_sha256 = ?, "
            "signature_base64 = 'pending-envelope-signature', key_id = ?, "
            "published_at = ?, published_by = ?, reason = ? "
            "WHERE id = ?",
            (
                json.dumps(policy, sort_keys=True, separators=(",", ":")),
                digest,
                # The key id is stable; the actual signature is applied to each
                # short-lived device-targeted envelope at fetch time.
                config.SIGNING_KEY_ID,
                now,
                principal.user_id,
                req.reason,
                latest["id"],
            ),
        )
        conn.execute(
            "UPDATE policies SET lifecycle_state = 'published', "
            "current_version = ?, published_by = ?, updated_at = ? WHERE id = ?",
            (publish_version, principal.user_id, now, policy_id),
        )
        assign_policy_to_fleet(conn, policy_id, publish_version, req.rollout_group or "all")
        write_audit(
            conn,
            actor=principal.user_id,
            action="policy.published",
            target_type="policy",
            target_id=policy_id,
            details={
                "version": publish_version,
                "digest": digest,
                "rollout_group": req.rollout_group or "all",
                "reason": req.reason,
            },
        )
        conn.commit()
        return {
            "status": "published",
            "policy_id": policy_id,
            "version": publish_version,
            "digest_sha256": digest,
        }
    finally:
        conn.close()


@router.post("/{policy_id}/rollback", status_code=202)
def rollback_policy(
    policy_id: str,
    req: RollbackPolicyRequest,
    principal: Annotated[Principal, Depends(require_role("security_admin"))] = None,
):
    conn = get_connection()
    try:
        row = _require_row(conn, policy_id)
        # Rollback is only meaningful from a settled, published policy.  If a
        # draft/submitted/approved change is pending, allowing rollback here
        # would publish unapproved content by copying it into a new version and
        # bypass the two-person lifecycle.
        if row["lifecycle_state"] != "published":
            raise HTTPException(
                status_code=409,
                detail="Rollback requires a published policy with no pending draft",
            )
        if row["created_by"] == principal.user_id:
            raise HTTPException(
                status_code=403,
                detail="Policy author cannot roll back their own policy",
            )
        current_version = int(row["current_version"] or 0)
        if req.target_version >= current_version:
            raise HTTPException(
                status_code=409,
                detail="Rollback target must be an earlier published version",
            )
        target = conn.execute(
            "SELECT * FROM policy_versions WHERE policy_id = ? AND version = ?",
            (policy_id, req.target_version),
        ).fetchone()
        if target is None:
            raise HTTPException(
                status_code=404,
                detail=f"Target version {req.target_version} not found",
            )
        latest = _latest_version_row(conn, policy_id)
        next_version = int(latest["version"]) + 1

        policy = json.loads(target["policy_json"])
        policy["policy_version"] = next_version
        policy["name"] = row["name"]
        _insert_version(
            conn,
            policy=policy,
            actor=principal.user_id,
            reason=req.reason,
            rollback_of=req.target_version,
        )
        now = utc_now_iso()
        conn.execute(
            "UPDATE policies SET lifecycle_state = 'published', "
            "current_version = ?, published_by = ?, updated_at = ? WHERE id = ?",
            (next_version, principal.user_id, now, policy_id),
        )
        assign_policy_to_fleet(conn, policy_id, next_version, "all")
        write_audit(
            conn,
            actor=principal.user_id,
            action="policy.rolled_back",
            target_type="policy",
            target_id=policy_id,
            details={
                "rollback_to": req.target_version,
                "new_version": next_version,
                "reason": req.reason,
            },
        )
        conn.commit()
        return {
            "status": "published",
            "policy_id": policy_id,
            "version": next_version,
            "rollback_of_version": req.target_version,
        }
    finally:
        conn.close()
