"""Policy envelope verification shared by the control plane and the agent.

This module deliberately has no dependency on server-side configuration or the
private signing key.  It implements SIGNING_SPEC.md sections 4, 5 and 6 so the
same code can be used by tests, the API, and the endpoint simulator.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

SPEC_VERSION = "1"
SIGNATURE_FIELD = "signature"
ENVELOPE_FIELDS = {
    "spec_version",
    "policy_id",
    "policy_version",
    "schema_version",
    "issued_at",
    "expires_at",
    "target_device_id",
    "digest_sha256",
    "key_id",
    "policy",
    SIGNATURE_FIELD,
}


class PolicyVerificationError(ValueError):
    """Raised when an envelope fails any normative verification step."""


@dataclass(frozen=True)
class VerificationResult:
    policy: dict[str, Any]
    policy_version: int
    policy_id: str
    key_id: str
    issued_at: str
    expires_at: str


def canonical_bytes(obj: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme bytes."""
    return rfc8785.dumps(obj)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def policy_digest(policy: dict[str, Any]) -> str:
    return sha256_hex(canonical_bytes(policy))


def _parse_rfc3339(value: str, name: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise PolicyVerificationError(f"{name} is missing")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyVerificationError(f"{name} is not RFC 3339: {exc}") from exc
    if parsed.tzinfo is None:
        raise PolicyVerificationError(f"{name} must include a UTC offset")
    return parsed.astimezone(UTC)


def _decode_signature(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise PolicyVerificationError("signature is missing")
    try:
        signature = base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001 - report a stable verification error
        raise PolicyVerificationError("signature is not valid base64") from exc
    if len(signature) != 64:
        raise PolicyVerificationError("signature must be exactly 64 bytes")
    return signature


def _decode_b64url(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:  # noqa: BLE001
        raise PolicyVerificationError("JWKS key is not valid base64url") from exc


def public_key_from_jwk(jwk: dict[str, Any]) -> Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise PolicyVerificationError("JWKS key is not an Ed25519 OKP key")
    raw = _decode_b64url(str(jwk.get("x", "")))
    if len(raw) != 32:
        raise PolicyVerificationError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def keys_by_id(jwks: dict[str, Any]) -> dict[str, dict[str, Any]]:
    keys = jwks.get("keys") if isinstance(jwks, dict) else None
    if not isinstance(keys, list):
        raise PolicyVerificationError("JWKS does not contain a keys array")
    result: dict[str, dict[str, Any]] = {}
    for key in keys:
        if isinstance(key, dict) and isinstance(key.get("kid"), str):
            result[key["kid"]] = key
    return result


def verify_envelope(
    envelope: dict[str, Any],
    jwks: dict[str, Any],
    expected_device_id: str,
    *,
    last_applied_version: int | None = None,
    now: datetime | None = None,
    clock_skew_seconds: int = 30,
    schema_version: str = "1.0.0",
    allow_same_version: bool = True,
) -> VerificationResult:
    """Verify a signed policy envelope in the order required by SIGNING_SPEC §6.

    Raises ``PolicyVerificationError`` with a stable, non-secret reason.  The
    caller must preserve the last-known-good policy and emit a
    ``policy.rejected`` event when this raises.
    """

    if not isinstance(envelope, dict):
        raise PolicyVerificationError("envelope must be a JSON object")

    unknown = set(envelope) - ENVELOPE_FIELDS
    if unknown:
        raise PolicyVerificationError(
            "envelope contains unknown fields: " + ", ".join(sorted(unknown))
        )

    if envelope.get("spec_version") != SPEC_VERSION:
        raise PolicyVerificationError("unsupported spec_version")

    if envelope.get("target_device_id") != expected_device_id:
        raise PolicyVerificationError("envelope is not targeted at this device")

    issued_at_dt = _parse_rfc3339(envelope.get("issued_at"), "issued_at")
    expires_at_dt = _parse_rfc3339(envelope.get("expires_at"), "expires_at")
    if expires_at_dt <= issued_at_dt:
        raise PolicyVerificationError("expires_at must be after issued_at")

    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        current = current.replace(tzinfo=UTC)
    skew = timedelta(seconds=max(0, clock_skew_seconds))
    if current + skew < issued_at_dt:
        raise PolicyVerificationError("policy is not valid yet")
    if current - skew > expires_at_dt:
        raise PolicyVerificationError("policy has expired")

    try:
        policy_version = int(envelope.get("policy_version"))
    except (TypeError, ValueError) as exc:
        raise PolicyVerificationError("policy_version must be an integer") from exc
    if policy_version < 1:
        raise PolicyVerificationError("policy_version must be positive")
    if last_applied_version is not None:
        if policy_version < last_applied_version:
            raise PolicyVerificationError("policy downgrade rejected")
        if policy_version == last_applied_version and not allow_same_version:
            raise PolicyVerificationError("policy version was already applied")

    key_id = envelope.get("key_id")
    if not isinstance(key_id, str) or not key_id:
        raise PolicyVerificationError("key_id is missing")
    key = keys_by_id(jwks).get(key_id)
    if key is None:
        raise PolicyVerificationError("unknown key_id")

    if envelope.get("schema_version") != schema_version:
        raise PolicyVerificationError("unsupported schema_version")

    policy = envelope.get("policy")
    if not isinstance(policy, dict):
        raise PolicyVerificationError("policy is missing")

    signature = _decode_signature(envelope.get(SIGNATURE_FIELD))
    unsigned = {k: v for k, v in envelope.items() if k != SIGNATURE_FIELD}
    public_key = public_key_from_jwk(key)
    try:
        public_key.verify(signature, canonical_bytes(unsigned))
    except InvalidSignature as exc:
        raise PolicyVerificationError("signature verification failed") from exc

    expected_digest = envelope.get("digest_sha256")
    if not isinstance(expected_digest, str):
        raise PolicyVerificationError("digest_sha256 is missing")
    if policy_digest(policy) != expected_digest.lower():
        raise PolicyVerificationError("policy digest does not match content")

    policy_id = envelope.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id:
        raise PolicyVerificationError("policy_id is missing")
    if policy.get("policy_id") != policy_id:
        raise PolicyVerificationError("policy_id does not match the inner policy")
    if policy.get("policy_version") != policy_version:
        raise PolicyVerificationError(
            "inner policy_version does not match the envelope"
        )

    return VerificationResult(
        policy=policy,
        policy_version=policy_version,
        policy_id=policy_id,
        key_id=key_id,
        issued_at=envelope["issued_at"],
        expires_at=envelope["expires_at"],
    )
