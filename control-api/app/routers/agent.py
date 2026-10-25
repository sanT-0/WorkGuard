from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from fastapi.responses import JSONResponse

from app import config
from app.audit import write_audit
from app.compliance import (
    ensure_assignment,
    get_assigned_policy,
    restore_heartbeat,
    update_compliance,
)
from app.database import get_connection, utc_now_iso
from app.schemas import (
    AgentEnrollRequest,
    AgentEnrollResponse,
    AgentEventsBatchRequest,
    AgentHeartbeatRequest,
    AgentPolicyResultsRequest,
    AgentReleaseCheckResponse,
    AgentUpdatesCheckRequest,
    RotateDeviceCredentialResponse,
)
from app.security import (
    generate_device_token,
    get_current_device,
    hash_device_token,
    hash_enrollment_code,
)
from app.signing import build_signed_envelope, jwks
from app.validation import (
    FieldValidationError,
    parse_timestamp,
    policy_control_ids,
    validate_event_type,
    validate_policy,
    validate_safe_details,
)

router = APIRouter(prefix="/agent", tags=["Agent"])


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat()


@router.get("/keys")
def policy_keys():
    """Public verification keys.  No secret material is exposed."""

    return JSONResponse(content=jwks(), headers={"Cache-Control": "public, max-age=300"})


@router.post("/enroll", response_model=AgentEnrollResponse, status_code=201)
def agent_enroll(req: AgentEnrollRequest):
    code_hash = hash_enrollment_code(req.enrollment_code)
    conn = get_connection()
    try:
        record = conn.execute(
            "SELECT * FROM enrollment_codes WHERE code_hash = ?", (code_hash,)
        ).fetchone()
        if not record:
            raise HTTPException(status_code=401, detail="Invalid enrollment code")
        if record["used_at"] is not None:
            raise HTTPException(status_code=401, detail="Enrollment code has already been used")

        expires_at = datetime.fromisoformat(record["expires_at"].replace("Z", "+00:00"))
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if datetime.now(UTC) > expires_at:
            conn.execute(
                "UPDATE enrollment_codes SET failed_attempts = failed_attempts + 1 "
                "WHERE code_hash = ?",
                (code_hash,),
            )
            conn.commit()
            raise HTTPException(status_code=401, detail="Enrollment code has expired")

        now = utc_now_iso()
        claimed = conn.execute(
            "UPDATE enrollment_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL",
            (now, code_hash),
        )
        if claimed.rowcount != 1:
            conn.rollback()
            raise HTTPException(status_code=409, detail="Enrollment code was already consumed")

        device_id = str(uuid.uuid4())
        display_name = f"WIN-{device_id[:6].upper()}-LAPTOP"
        token = generate_device_token()
        token_hash = hash_device_token(token)

        conn.execute(
            "INSERT INTO devices "
            "(id, org_id, display_name, assigned_user_id, os_version, os_edition, "
            " agent_version, status, last_seen_at, device_public_key, "
            " credential_hash, credential_issued_at, created_at) "
            "VALUES (?, 'org-default', ?, ?, ?, ?, ?, 'enrolled', ?, ?, ?, ?, ?)",
            (
                device_id,
                display_name,
                record["requested_for_user_id"],
                req.os_version,
                req.os_edition or "Windows 11 Enterprise",
                req.agent_version,
                now,
                req.device_public_key,
                token_hash,
                now,
                now,
            ),
        )
        conn.execute(
            "UPDATE enrollment_codes SET used_by_device_id = ? WHERE code_hash = ?",
            (device_id, code_hash),
        )
        ensure_assignment(conn, device_id)
        assignment = get_assigned_policy(conn, device_id)
        if assignment:
            conn.execute(
                "UPDATE devices SET policy_version_desired = ? WHERE id = ?",
                (assignment["desired_version"], device_id),
            )
        write_audit(
            conn,
            actor=f"agent:{device_id}",
            action="device.enrolled",
            target_type="device",
            target_id=device_id,
            details={"display_name": display_name, "os": req.os_version},
        )
        conn.commit()
        return {
            "device_id": device_id,
            "device_token": token,
            "expires_at": expires_at.isoformat(),
        }
    finally:
        conn.close()


@router.post("/heartbeat", status_code=202)
def agent_heartbeat(
    req: AgentHeartbeatRequest,
    device: Annotated[dict, Depends(get_current_device)],
):
    try:
        parse_timestamp(req.observed_at, "observed_at")
    except FieldValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    conn = get_connection()
    try:
        now = utc_now_iso()
        observed = req.current_policy_version
        if observed is not None and device.get("policy_version_observed") is not None:
            observed = max(observed, int(device["policy_version_observed"]))
        conn.execute(
            "UPDATE devices SET last_seen_at = ?, agent_version = ?, os_version = ?, "
            "os_edition = COALESCE(?, os_edition), policy_version_observed = "
            "COALESCE(?, policy_version_observed) WHERE id = ?",
            (
                now,
                req.agent_version,
                req.os_version,
                req.os_edition,
                observed,
                device["id"],
            ),
        )
        restore_heartbeat(conn, device["id"], observed)
        conn.commit()
        assignment = get_assigned_policy(conn, device["id"])
        return {
            "status": "heartbeat_acknowledged",
            "last_seen_at": now,
            "desired_policy_version": assignment["desired_version"] if assignment else None,
            "next_heartbeat_seconds": max(30, config.DEVICE_STALE_AFTER_SECONDS // 3),
        }
    finally:
        conn.close()


@router.get("/policies/current")
def get_current_policy(device: Annotated[dict, Depends(get_current_device)]):
    conn = get_connection()
    try:
        assignment = get_assigned_policy(conn, device["id"])
        if assignment is None:
            return Response(status_code=204)
        policy = assignment["policy"]
        validate_policy(policy)
        envelope = build_signed_envelope(policy, device["id"])
        response = JSONResponse(content=envelope)
        response.headers["Cache-Control"] = "no-store"
        return response
    finally:
        conn.close()


@router.post("/credential/rotate", response_model=RotateDeviceCredentialResponse)
def rotate_credential(device: Annotated[dict, Depends(get_current_device)]):
    token = generate_device_token()
    issued = utc_now_iso()
    conn = get_connection()
    try:
        conn.execute(
            "UPDATE devices SET credential_hash = ?, credential_issued_at = ? WHERE id = ?",
            (hash_device_token(token), issued, device["id"]),
        )
        write_audit(
            conn,
            actor=f"agent:{device['id']}",
            action="device.credential_rotated",
            target_type="device",
            target_id=device["id"],
            details={"issued_at": issued},
        )
        conn.commit()
        return {"device_id": device["id"], "device_token": token, "issued_at": issued}
    finally:
        conn.close()


@router.post("/policy-results", status_code=202)
def post_policy_results(
    req: AgentPolicyResultsRequest,
    device: Annotated[dict, Depends(get_current_device)],
):
    try:
        parse_timestamp(req.observed_at, "observed_at")
    except FieldValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    conn = get_connection()
    try:
        assignment = get_assigned_policy(conn, device["id"])
        if assignment is None:
            raise HTTPException(status_code=409, detail="Device has no assigned policy")
        if req.policy_version not in {
            assignment["desired_version"],
            device.get("last_applied_version"),
        }:
            raise HTTPException(status_code=409, detail="Unknown policy version")

        allowed_controls = policy_control_ids(assignment["policy"])
        for result in req.controls:
            if result.control_id not in allowed_controls:
                raise HTTPException(
                    status_code=422,
                    detail=f"Unknown control_id: {result.control_id}",
                )
            if result.error_code and len(result.error_code) > 120:
                raise HTTPException(status_code=422, detail="error_code is too long")
            try:
                safe_details = validate_safe_details(result.safe_details)
            except FieldValidationError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc

            conn.execute(
                "INSERT INTO control_results "
                "(id, device_id, policy_version, control_id, status, provider, "
                " observed_at, error_code, safe_details) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(device_id, policy_version, control_id) DO UPDATE SET "
                " status = excluded.status, provider = excluded.provider, "
                " observed_at = excluded.observed_at, error_code = excluded.error_code, "
                " safe_details = excluded.safe_details",
                (
                    str(uuid.uuid4()),
                    device["id"],
                    req.policy_version,
                    result.control_id,
                    result.status,
                    result.provider[:200],
                    result.observed_at,
                    result.error_code,
                    safe_details,
                ),
            )

        observed = req.policy_version
        if device.get("policy_version_observed") is not None:
            observed = max(observed, int(device["policy_version_observed"]))
        conn.execute(
            "UPDATE devices SET policy_version_observed = ?, "
            "last_applied_version = MAX(COALESCE(last_applied_version, 0), ?) "
            "WHERE id = ?",
            (observed, req.policy_version, device["id"]),
        )
        # Evaluate against the currently desired version, never against the
        # version the agent happened to report.  Otherwise an agent could keep
        # reporting results for an old version and appear compliant after a
        # newer policy was published.
        derived = update_compliance(conn, device["id"])
        conn.commit()
        return {
            "status": "results_accepted",
            "derived_device_status": derived,
        }
    finally:
        conn.close()


@router.post("/events:batch", status_code=202)
def post_events_batch(
    req: AgentEventsBatchRequest,
    device: Annotated[dict, Depends(get_current_device)],
):
    if len(req.events) > config.MAX_EVENT_BATCH_SIZE:
        raise HTTPException(
            status_code=413,
            detail=f"Batch exceeds {config.MAX_EVENT_BATCH_SIZE} events",
        )

    conn = get_connection()
    try:
        accepted = 0
        for event in req.events:
            try:
                validate_event_type(event.event_type)
                parse_timestamp(event.occurred_at, "occurred_at")
            except FieldValidationError as exc:
                raise HTTPException(status_code=422, detail=str(exc)) from exc
            if event.device_id and event.device_id != device["id"]:
                raise HTTPException(
                    status_code=403,
                    detail="Event device_id does not match the authenticated device",
                )
            event_id = event.id or str(uuid.uuid4())
            cursor = conn.execute(
                "INSERT OR IGNORE INTO security_events "
                "(id, device_id, event_type, severity, occurred_at, source, "
                " response_state) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    device["id"],
                    event.event_type,
                    event.severity,
                    event.occurred_at,
                    event.source[:120],
                    event.response_state[:120],
                ),
            )
            accepted += cursor.rowcount
        conn.commit()
        return {"status": "events_accepted", "count": accepted, "submitted": len(req.events)}
    finally:
        conn.close()


@router.post("/updates/check", response_model=AgentReleaseCheckResponse)
def check_updates(
    req: AgentUpdatesCheckRequest,
    device: Annotated[dict, Depends(get_current_device)],
):
    # No release feed is configured in the MVP.  Returning an unsigned or
    # guessed artifact would violate the signed-update requirement.
    return {
        "update_available": False,
        "release_version": req.current_version,
        "mandatory": False,
    }
