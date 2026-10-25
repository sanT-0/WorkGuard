from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.policy_verify import (
    PolicyVerificationError,
    policy_digest,
    verify_envelope,
)
from app.seed import _demo_policy
from app.signing import build_signed_envelope, jwks
from app.validation import PolicyValidationError, validate_policy


def _envelope(**kwargs):
    policy = _demo_policy()
    policy["policy_version"] = 2
    return policy, build_signed_envelope(policy, "device-1", **kwargs)


def test_valid_envelope_verifies():
    policy, envelope = _envelope()
    result = verify_envelope(envelope, jwks(), "device-1", last_applied_version=1)
    assert result.policy_version == 2
    assert result.policy["name"] == policy["name"]
    assert envelope["digest_sha256"] == policy_digest(policy)
    assert "algorithm" not in envelope
    assert envelope["spec_version"] == "1"


def test_tampered_policy_is_rejected():
    _, envelope = _envelope()
    envelope["policy"]["controls"][0]["settings"]["action"] = "allow"
    with pytest.raises(PolicyVerificationError, match="signature"):
        verify_envelope(envelope, jwks(), "device-1")


def test_wrong_device_is_rejected():
    _, envelope = _envelope()
    with pytest.raises(PolicyVerificationError, match="targeted"):
        verify_envelope(envelope, jwks(), "device-2")


def test_expired_and_not_yet_valid_are_rejected():
    now = datetime.now(UTC)
    _, expired = _envelope(
        issued_at=now - timedelta(hours=2), expires_at=now - timedelta(hours=1)
    )
    with pytest.raises(PolicyVerificationError, match="expired"):
        verify_envelope(expired, jwks(), "device-1")

    _, future = _envelope(
        issued_at=now + timedelta(hours=1), expires_at=now + timedelta(hours=2)
    )
    with pytest.raises(PolicyVerificationError, match="not valid yet"):
        verify_envelope(future, jwks(), "device-1")


def test_unknown_key_id_is_rejected():
    _, envelope = _envelope()
    envelope["key_id"] = "unknown-key"
    with pytest.raises(PolicyVerificationError, match="unknown key_id"):
        verify_envelope(envelope, jwks(), "device-1")


def test_wrong_spec_version_is_rejected():
    _, envelope = _envelope()
    envelope["spec_version"] = "99"
    with pytest.raises(PolicyVerificationError, match="spec_version"):
        verify_envelope(envelope, jwks(), "device-1")


def test_downgrade_is_rejected():
    _, envelope = _envelope()
    with pytest.raises(PolicyVerificationError, match="downgrade"):
        verify_envelope(envelope, jwks(), "device-1", last_applied_version=3)


def test_unknown_envelope_field_is_rejected():
    _, envelope = _envelope()
    envelope["extra"] = True
    with pytest.raises(PolicyVerificationError, match="unknown fields"):
        verify_envelope(envelope, jwks(), "device-1")


def test_invalid_policy_settings_are_rejected_by_schema():
    policy = _demo_policy()
    policy["controls"][0]["settings"]["action"] = "allow-everything"
    with pytest.raises(PolicyValidationError):
        validate_policy(policy)


def test_default_policy_is_schema_valid():
    validate_policy(_demo_policy())
