"""Request and policy validation helpers.

The canonical JSON Schema in ``schemas/policy.schema.json`` is the single source
of truth for control settings.  The API validates every draft, edit, submit,
approve and publish against it, so an invalid setting can never reach an agent.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from app import config

_SCHEMA_PATH = config.REPO_ROOT / "schemas" / "policy.schema.json"
_validator: Draft202012Validator | None = None

_SAFE_DETAILS_DENY = re.compile(
    r"(-----BEGIN |authorization\s*:|bearer\s+[A-Za-z0-9._-]{16,}|"
    r"password\s*=|secret\s*=|token\s*=|api[_-]?key\s*=|"
    r"\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9]{20,}\b|"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
)

_EVENT_TYPE = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,119}$")


class PolicyValidationError(ValueError):
    """Raised when a policy does not conform to the canonical schema."""


class FieldValidationError(ValueError):
    """Raised when an event/result field is outside the allowlist."""


def _get_validator() -> Draft202012Validator:
    global _validator
    if _validator is None:
        schema = json.loads(Path(_SCHEMA_PATH).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        _validator = Draft202012Validator(schema)
    return _validator


def validate_policy(policy: dict[str, Any]) -> None:
    """Validate a complete policy object, including per-control settings."""

    if not isinstance(policy, dict):
        raise PolicyValidationError("policy must be an object")

    errors = sorted(
        _get_validator().iter_errors(policy), key=lambda error: list(error.path)
    )
    if errors:
        messages = []
        for error in errors[:10]:
            location = ".".join(str(part) for part in error.path) or "<root>"
            messages.append(f"{location}: {error.message}")
        raise PolicyValidationError("; ".join(messages))

    controls = policy.get("controls", [])
    control_ids = [control.get("control_id") for control in controls]
    if len(control_ids) != len(set(control_ids)):
        raise PolicyValidationError("control_id values must be unique")


def policy_control_ids(policy: dict[str, Any]) -> set[str]:
    return {
        str(control.get("control_id"))
        for control in policy.get("controls", [])
        if isinstance(control, dict)
    }


def required_control_ids(policy: dict[str, Any]) -> set[str]:
    return {
        str(control.get("control_id"))
        for control in policy.get("controls", [])
        if isinstance(control, dict) and control.get("required") is True
    }


def validate_safe_details(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise FieldValidationError("safe_details must be a string")
    if len(value) > 1000:
        raise FieldValidationError("safe_details must be at most 1000 characters")
    if any(ord(ch) < 0x20 and ch not in "\n\t" for ch in value):
        raise FieldValidationError("safe_details contains control characters")
    if _SAFE_DETAILS_DENY.search(value):
        raise FieldValidationError(
            "safe_details appears to contain a secret, token, credential or email address"
        )
    return value


def validate_event_type(value: str) -> str:
    if not isinstance(value, str) or not _EVENT_TYPE.match(value):
        raise FieldValidationError(
            "event_type must match ^[a-z0-9][a-z0-9._:-]{0,119}$"
        )
    return value


def parse_timestamp(
    value: str,
    field: str,
    *,
    max_past: timedelta = timedelta(days=30),
    max_future: timedelta = timedelta(minutes=5),
    now: datetime | None = None,
) -> datetime:
    if not isinstance(value, str) or not value:
        raise FieldValidationError(f"{field} is required")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise FieldValidationError(f"{field} is not RFC 3339") from exc
    if parsed.tzinfo is None:
        raise FieldValidationError(f"{field} must include a UTC offset")
    parsed = parsed.astimezone(UTC)
    current = now or datetime.now(UTC)
    if parsed < current - max_past:
        raise FieldValidationError(f"{field} is too far in the past")
    if parsed > current + max_future:
        raise FieldValidationError(f"{field} is too far in the future")
    return parsed
