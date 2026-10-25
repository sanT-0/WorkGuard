"""Administrator and device authentication / authorization."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Annotated, Any

import jwt
from fastapi import Depends, Header, HTTPException, Request, status

from app import config
from app.database import get_connection

ROLE_RANK = {"auditor": 1, "it_operator": 2, "security_admin": 3}
ROLE_LABELS = {
    "security_admin": "security administrator",
    "it_operator": "IT operator",
    "auditor": "auditor",
}


@dataclass(frozen=True)
class Principal:
    user_id: str
    role: str
    org_id: str = "org-default"

    @property
    def rank(self) -> int:
        return ROLE_RANK.get(self.role, 0)


def _highest_role(roles: set[str]) -> str | None:
    normalized = {role.strip().lower() for role in roles if role.strip()}
    aliases = {
        "admin": "security_admin",
        "security-admin": "security_admin",
        "securityadmin": "security_admin",
        "operator": "it_operator",
        "it-operator": "it_operator",
        "readonly": "auditor",
        "read-only": "auditor",
    }
    normalized = {aliases.get(role, role) for role in normalized}
    candidates = [role for role in normalized if role in ROLE_RANK]
    if not candidates:
        return None
    return max(candidates, key=lambda role: ROLE_RANK[role])


def _extract_roles(claims: dict[str, Any]) -> set[str]:
    roles: set[str] = set()
    direct = claims.get(config.OIDC_ROLE_CLAIM)
    if isinstance(direct, str):
        roles.update(direct.replace(",", " ").split())
    elif isinstance(direct, list):
        roles.update(str(item) for item in direct)

    realm = claims.get("realm_access")
    if isinstance(realm, dict) and isinstance(realm.get("roles"), list):
        roles.update(str(item) for item in realm["roles"])

    groups = claims.get("groups")
    if isinstance(groups, list):
        roles.update(str(item) for item in groups)

    scope = claims.get("scope")
    if isinstance(scope, str):
        roles.update(scope.split())

    return roles


_jwks_clients: dict[str, jwt.PyJWKClient] = {}


def _jwks_client() -> jwt.PyJWKClient:
    url = config.OIDC_JWKS_URL
    if not url:
        if not config.OIDC_ISSUER_URL:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="OIDC is not configured",
            )
        url = config.OIDC_ISSUER_URL + "/.well-known/jwks.json"
    client = _jwks_clients.get(url)
    if client is None:
        client = jwt.PyJWKClient(url, cache_keys=True, lifespan=300)
        _jwks_clients[url] = client
    return client


def _verify_oidc_bearer(token: str) -> Principal:
    if not config.OIDC_ISSUER_URL or not config.OIDC_AUDIENCE:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC issuer/audience is not configured",
        )
    try:
        signing_key = _jwks_client().get_signing_key_from_jwt(token)
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256", "ES256", "EdDSA"],
            audience=config.OIDC_AUDIENCE,
            issuer=config.OIDC_ISSUER_URL,
            options={"require": ["exp", "iss", "aud", "sub"]},
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    role = _highest_role(_extract_roles(claims))
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token does not carry a WorkGuard role",
        )
    return Principal(
        user_id=str(claims.get("sub") or claims.get("email") or "unknown"),
        role=role,
        org_id=str(claims.get("org_id") or "org-default"),
    )


def get_admin_principal(
    request: Request,
    authorization: Annotated[str | None, Header()] = None,
    x_dev_user: Annotated[str | None, Header()] = None,
    x_dev_role: Annotated[str | None, Header()] = None,
) -> Principal:
    """Resolve an administrator identity or fail closed.

    Local development may use ``X-Dev-User`` / ``X-Dev-Role`` headers only when
    ``APP_ENV=local``, ``AUTH_MODE=dev`` and ``ALLOW_DEV_AUTH=1``.  The defaults
    exist so the bundled console is immediately usable; the mode itself is
    impossible to enable outside local development.
    """

    if config.DEV_AUTH_ALLOWED:
        role = (x_dev_role or "security_admin").strip().lower()
        if role not in ROLE_RANK:
            raise HTTPException(status_code=403, detail="Unknown development role")
        return Principal(
            user_id=(x_dev_user or "dev-admin").strip() or "dev-admin",
            role=role,
        )

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Administrator authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _verify_oidc_bearer(authorization.split(" ", 1)[1].strip())


def require_role(minimum: str):
    if minimum not in ROLE_RANK:
        raise ValueError(f"Unknown role {minimum}")

    def dependency(
        principal: Annotated[Principal, Depends(get_admin_principal)],
    ) -> Principal:
        if principal.rank < ROLE_RANK[minimum]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {ROLE_LABELS[minimum]} role or higher",
            )
        return principal

    return dependency


def hash_enrollment_code(code: str) -> str:
    return hmac.new(
        config.ENROLLMENT_CODE_PEPPER.encode("utf-8"),
        code.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def hash_device_token(token: str) -> str:
    return hmac.new(
        config.DEVICE_TOKEN_PEPPER.encode("utf-8"),
        token.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_device_token() -> str:
    return "wg1_" + secrets.token_urlsafe(32)


def generate_enrollment_code() -> str:
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"  # RFC 4648 Base32
    return "WG-" + "".join(secrets.choice(alphabet) for _ in range(26))


def get_current_device(
    authorization: Annotated[str | None, Header()] = None,
    x_device_id: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Authenticate an agent request and return its device row.

    The device identity is derived from the bearer credential.  The legacy
    ``X-Device-Id`` header is accepted only when explicitly enabled in a local
    development environment.
    """

    conn = get_connection()
    try:
        row = None
        if authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1].strip()
            token_hash = hash_device_token(token)
            row = conn.execute(
                "SELECT * FROM devices WHERE credential_hash = ?", (token_hash,)
            ).fetchone()

        if (
            row is None
            and config.DEV_AUTH_ALLOWED
            and config.ALLOW_INSECURE_DEVICE_HEADER
            and x_device_id
        ):
            row = conn.execute(
                "SELECT * FROM devices WHERE id = ?", (x_device_id,)
            ).fetchone()

        if row is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Device authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if row["status"] == "revoked":
            raise HTTPException(status_code=403, detail="Device has been revoked")
        return dict(row)
    finally:
        conn.close()
