"""Central configuration for the WorkGuard control plane.

Environment variables are read once at import time.  Local development is
allowed to use a deliberately simple header-based auth mode, but that mode is
only available when ``APP_ENV=local`` and ``AUTH_MODE=dev``.  Any other
combination fails closed at request time.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # control-api/
REPO_ROOT = BASE_DIR.parent


def _bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


APP_ENV = os.getenv("APP_ENV", "local").strip().lower()
AUTH_MODE = os.getenv(
    "AUTH_MODE", "dev" if APP_ENV == "local" else "oidc"
).strip().lower()

# Dev auth is a local-only convenience.  It must never be enabled in staging or
# production, and an explicit opt-in keeps a misconfigured deployment from
# silently accepting forged identity headers.
DEV_AUTH_ALLOWED = (
    APP_ENV == "local" and AUTH_MODE == "dev" and _bool("ALLOW_DEV_AUTH", False)
)

# Local fallback for the agent simulator.  Disabled by default so the secure
# path is the default even in local development.
ALLOW_INSECURE_DEVICE_HEADER = _bool("ALLOW_INSECURE_DEVICE_HEADER", False)

# Admin OIDC settings (required when AUTH_MODE=oidc).
OIDC_ISSUER_URL = os.getenv("OIDC_ISSUER_URL", "").rstrip("/")
OIDC_AUDIENCE = os.getenv("OIDC_AUDIENCE", "")
OIDC_JWKS_URL = os.getenv("OIDC_JWKS_URL", "")
OIDC_ROLE_CLAIM = os.getenv("OIDC_ROLE_CLAIM", "roles")

DB_PATH = Path(os.getenv("WG_DB_PATH", str(BASE_DIR / "workguard.db")))

SIGNING_KEY_PATH = Path(
    os.getenv("POLICY_SIGNING_KEY_PATH", str(BASE_DIR / ".local" / "policy_signing_key.pem"))
)
SIGNING_KEY_ID = os.getenv("POLICY_SIGNING_KEY_ID", "wg-policy-local-v1")
if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", SIGNING_KEY_ID):
    raise RuntimeError(
        "POLICY_SIGNING_KEY_ID must match [A-Za-z0-9_-]{1,128} (SIGNING_SPEC.md §4)."
    )
POLICY_ENVELOPE_TTL_SECONDS = _int("POLICY_ENVELOPE_TTL_SECONDS", 3600)
POLICY_CLOCK_SKEW_SECONDS = _int("POLICY_CLOCK_SKEW_SECONDS", 30)

# Enrollment and device credentials.
ENROLLMENT_CODE_TTL_SECONDS = _int("ENROLLMENT_CODE_TTL_SECONDS", 300)
_DEFAULT_ENROLLMENT_PEPPER = "local-dev-enrollment-pepper-change-me"
_DEFAULT_DEVICE_PEPPER = "local-dev-device-pepper-change-me"
ENROLLMENT_CODE_PEPPER = os.getenv(
    "ENROLLMENT_CODE_PEPPER", _DEFAULT_ENROLLMENT_PEPPER
)
DEVICE_TOKEN_PEPPER = os.getenv("DEVICE_TOKEN_PEPPER", _DEFAULT_DEVICE_PEPPER)
DEVICE_TOKEN_FILE = Path(
    os.getenv("WG_DEVICE_TOKEN_FILE", str(BASE_DIR / ".dev-device-tokens.json"))
)

# Fleet health.
DEVICE_STALE_AFTER_SECONDS = _int("DEVICE_STALE_AFTER_SECONDS", 1800)
DEVICE_WARN_AFTER_SECONDS = _int("DEVICE_WARN_AFTER_SECONDS", 600)
STALE_SWEEP_INTERVAL_SECONDS = _int("STALE_SWEEP_INTERVAL_SECONDS", 60)

# Event ingestion limits.
MAX_EVENT_BATCH_SIZE = _int("MAX_EVENT_BATCH_SIZE", 100)
MAX_EVENT_PAYLOAD_BYTES = _int("MAX_EVENT_PAYLOAD_BYTES", 262_144)

# HTTP / deployment.
CORS_ORIGINS = [
    item.strip()
    for item in os.getenv(
        "CORS_ORIGINS", "http://127.0.0.1:8000,http://localhost:8000"
    ).split(",")
    if item.strip()
]
RATE_LIMIT_ENABLED = _bool("RATE_LIMIT_ENABLED", True)
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip("/")

# Signing keys and credential peppers are required outside local development.
# Failing here is deliberate: a deployment must not silently start with the
# development key or a publicly known hash pepper.
if APP_ENV != "local":
    if not SIGNING_KEY_PATH.exists():
        raise RuntimeError(
            "Policy signing key is missing. Configure POLICY_SIGNING_KEY_PATH with a "
            "KMS/HSM-backed key before starting in a non-local environment."
        )
    if ENROLLMENT_CODE_PEPPER == _DEFAULT_ENROLLMENT_PEPPER:
        raise RuntimeError(
            "ENROLLMENT_CODE_PEPPER is still the development default. Set a random, "
            "secret value from a secret manager."
        )
    if DEVICE_TOKEN_PEPPER == _DEFAULT_DEVICE_PEPPER:
        raise RuntimeError(
            "DEVICE_TOKEN_PEPPER is still the development default. Set a random, "
            "secret value from a secret manager."
        )
