"""Ed25519 policy signing and verification-key publication.

The private key is never embedded in source.  Local development generates a
key in ``control-api/.local`` (git-ignored); every other environment must point
``POLICY_SIGNING_KEY_PATH`` at a key materialised by a KMS/HSM or secret
manager.  Key rotation is expressed through ``POLICY_SIGNING_KEY_ID`` and the
published JWKS.
"""

from __future__ import annotations

import base64
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app import config
from app.policy_verify import (
    SPEC_VERSION,
    canonical_bytes,
    policy_digest,
    verify_envelope,
)

_private_key: Ed25519PrivateKey | None = None


def utc_now() -> datetime:
    return datetime.now(UTC)


def iso_z(value: datetime | None = None) -> str:
    value = (value or utc_now()).astimezone(UTC).replace(microsecond=0)
    return value.isoformat().replace("+00:00", "Z")


def _load_or_create_private_key() -> Ed25519PrivateKey:
    global _private_key
    if _private_key is not None:
        return _private_key

    path: Path = config.SIGNING_KEY_PATH
    if path.exists():
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise RuntimeError("Configured policy signing key is not Ed25519")
    else:
        if config.APP_ENV != "local":
            raise RuntimeError(
                "Refusing to generate a policy signing key outside local development"
            )
        path.parent.mkdir(parents=True, exist_ok=True)
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path.write_bytes(pem)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    _private_key = key
    return key


def reset_key_cache() -> None:
    """Test helper: force the next call to reload the key from disk."""
    global _private_key
    _private_key = None


def public_key() -> Ed25519PublicKey:
    return _load_or_create_private_key().public_key()


def public_key_b64url() -> str:
    raw = public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def jwks() -> dict[str, Any]:
    return {
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": public_key_b64url(),
                "kid": config.SIGNING_KEY_ID,
                "use": "sig",
                "alg": "EdDSA",
            }
        ]
    }


def sign_bytes(payload: bytes) -> bytes:
    return _load_or_create_private_key().sign(payload)


def build_signed_envelope(
    policy: dict[str, Any],
    target_device_id: str,
    *,
    ttl_seconds: int | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    """Build and sign the normative envelope from SIGNING_SPEC §4."""

    issued = issued_at or utc_now()
    expires = expires_at or (
        issued + timedelta(seconds=ttl_seconds or config.POLICY_ENVELOPE_TTL_SECONDS)
    )
    envelope: dict[str, Any] = {
        "spec_version": SPEC_VERSION,
        "policy_id": policy["policy_id"],
        "policy_version": int(policy["policy_version"]),
        "schema_version": policy.get("schema_version", "1.0.0"),
        "issued_at": iso_z(issued),
        "expires_at": iso_z(expires),
        "target_device_id": target_device_id,
        "digest_sha256": policy_digest(policy),
        "key_id": config.SIGNING_KEY_ID,
        "policy": policy,
    }
    signature = sign_bytes(canonical_bytes(envelope))
    envelope["signature"] = base64.b64encode(signature).decode("ascii")
    return envelope


def verify_signed_envelope(
    envelope: dict[str, Any],
    expected_device_id: str,
    *,
    last_applied_version: int | None = None,
    now: datetime | None = None,
):
    """Convenience wrapper used by tests and admin verification actions."""

    return verify_envelope(
        envelope,
        jwks(),
        expected_device_id,
        last_applied_version=last_applied_version,
        now=now,
        clock_skew_seconds=config.POLICY_CLOCK_SKEW_SECONDS,
    )
