from __future__ import annotations

import asyncio
import logging
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from app import config
from app.compliance import refresh_stale_devices
from app.database import InvalidCursorError, init_db
from app.routers import (
    admin_devices,
    admin_events,
    admin_exceptions,
    admin_policies,
    agent,
    health,
)
from app.seed import seed
from app.validation import FieldValidationError, PolicyValidationError

logger = logging.getLogger("workguard")
logging.basicConfig(level=logging.INFO)


class RateLimiter:
    """Small in-process fixed-window limiter for the MVP.

    A production deployment must enforce the same limits at the edge or in a
    shared Redis-backed limiter so multiple API replicas cannot be bypassed.
    """

    def __init__(self) -> None:
        self._windows: dict[tuple[str, str], tuple[float, int]] = {}

    def allow(self, key: str, limit: int, window_seconds: int = 60) -> bool:
        now = time.monotonic()
        if len(self._windows) > 4096:
            cutoff = now - 600
            for bucket_key, (started_at, _) in list(self._windows.items()):
                if started_at < cutoff:
                    self._windows.pop(bucket_key, None)
        bucket = (key, str(window_seconds))
        started, count = self._windows.get(bucket, (now, 0))
        if now - started >= window_seconds:
            started, count = now, 0
        count += 1
        self._windows[bucket] = (started, count)
        return count <= limit


limiter = RateLimiter()
RATE_LIMITS: list[tuple[str, int]] = [
    ("/api/v1/agent/enroll", 10),
    ("/api/v1/agent/heartbeat", 120),
    ("/api/v1/agent/policies/current", 120),
    ("/api/v1/agent/policy-results", 60),
    ("/api/v1/agent/events:batch", 120),
    ("/api/v1/admin/enrollment-codes", 20),
]


async def stale_sweeper() -> None:
    while True:
        try:
            await asyncio.to_thread(refresh_stale_devices)
        except Exception:  # noqa: BLE001 - keep the sweep alive
            logger.exception("stale sweep failed")
        await asyncio.sleep(max(10, config.STALE_SWEEP_INTERVAL_SECONDS))


@asynccontextmanager
async def lifespan(app: FastAPI):
    if config.DEV_AUTH_ALLOWED:
        logger.warning(
            "Development authentication is ENABLED (APP_ENV=local, AUTH_MODE=dev, "
            "ALLOW_DEV_AUTH=1). Never expose this process beyond localhost."
        )
    init_db()
    seed()
    task = asyncio.create_task(stale_sweeper())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(
    title="WorkGuard Control API",
    version="1.1.0",
    description=(
        "Endpoint policy orchestration and device security telemetry control "
        "plane. Policy signing follows SIGNING_SPEC.md (Ed25519 + RFC 8785)."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Idempotency-Key", "X-Dev-User", "X-Dev-Role"],
    expose_headers=["X-Request-ID"],
    max_age=600,
)


_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


@app.middleware("http")
async def request_guard(request: Request, call_next):
    incoming = request.headers.get("X-Request-ID")
    request_id = incoming if incoming and _REQUEST_ID.match(incoming) else str(uuid.uuid4())
    request.state.request_id = request_id

    if config.RATE_LIMIT_ENABLED:
        client = request.client.host if request.client else "unknown"
        for prefix, limit in RATE_LIMITS:
            if request.url.path == prefix and not limiter.allow(f"{client}:{prefix}", limit):
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": {
                            "code": "RATE_LIMITED",
                            "message": "Too many requests. Try again shortly.",
                            "request_id": request_id,
                        }
                    },
                    headers={"Retry-After": "60", "X-Request-ID": request_id},
                )

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > config.MAX_EVENT_PAYLOAD_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": {
                            "code": "PAYLOAD_TOO_LARGE",
                            "message": "Request body exceeds the configured limit.",
                            "request_id": request_id,
                        }
                    },
                    headers={"X-Request-ID": request_id},
                )
        except ValueError:
            pass

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'",
    )
    if config.APP_ENV != "local":
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
    headers = dict(exc.headers or {})
    headers["X-Request-ID"] = request_id
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": f"HTTP_{exc.status_code}",
                "message": detail,
                "request_id": request_id,
            }
        },
        headers=headers,
    )


@app.exception_handler(PolicyValidationError)
@app.exception_handler(FieldValidationError)
async def domain_validation_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": str(exc),
                "request_id": request_id,
            }
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(InvalidCursorError)
async def invalid_cursor_handler(request: Request, exc: InvalidCursorError):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "INVALID_CURSOR",
                "message": str(exc),
                "request_id": request_id,
            }
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    messages = []
    for error in exc.errors()[:10]:
        location = ".".join(str(part) for part in error.get("loc", ()))
        messages.append(f"{location}: {error.get('msg', 'invalid value')}")
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "; ".join(messages) or "Invalid request",
                "request_id": request_id,
            }
        },
        headers={"X-Request-ID": request_id},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    request_id = getattr(request.state, "request_id", str(uuid.uuid4()))
    logger.exception("Unhandled request error request_id=%s", request_id)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": "INTERNAL_ERROR",
                "message": "An internal error occurred. Use the request id to contact support.",
                "request_id": request_id,
            }
        },
        headers={"X-Request-ID": request_id},
    )


app.include_router(health.router)
app.include_router(admin_devices.router, prefix="/api/v1")
app.include_router(admin_policies.router, prefix="/api/v1")
app.include_router(admin_events.router, prefix="/api/v1")
app.include_router(admin_exceptions.router, prefix="/api/v1")
app.include_router(agent.router, prefix="/api/v1")


@app.get("/api/v1")
def api_root():
    return {
        "service": "WorkGuard Control Plane",
        "version": "1.1.0",
        "status": "online",
        "auth_mode": "dev" if config.DEV_AUTH_ALLOWED else "oidc",
        "stale_after_seconds": config.DEVICE_STALE_AFTER_SECONDS,
        "docs_url": "/docs",
        "openapi_url": "/openapi.json",
    }


_web_dist = Path(__file__).resolve().parent.parent.parent / "admin-web" / "dist"
_web_src = Path(__file__).resolve().parent.parent.parent / "admin-web"
_web_root = _web_dist if _web_dist.exists() else _web_src
if _web_root.exists():
    app.mount("/", StaticFiles(directory=str(_web_root), html=True), name="static")
