from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from app.database import init_db
from app.seed import seed
from app.routers import health, admin_devices, admin_policies, admin_events, admin_exceptions, agent

app = FastAPI(
    title="WorkGuard Control API",
    version="1.0.0",
    description="Enterprise endpoint policy orchestration and device security telemetry control plane."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()
seed()

app.include_router(health.router)
app.include_router(admin_devices.router, prefix="/api/v1")
app.include_router(admin_policies.router, prefix="/api/v1")
app.include_router(admin_events.router, prefix="/api/v1")
app.include_router(admin_exceptions.router, prefix="/api/v1")
app.include_router(agent.router, prefix="/api/v1")

web_dist = os.path.join(os.path.dirname(__file__), "..", "..", "admin-web", "dist")
if os.path.exists(web_dist):
    app.mount("/", StaticFiles(directory=web_dist, html=True), name="static")

@app.get("/api/v1")
def api_root():
    return {
        "service": "WorkGuard Control Plane",
        "version": "1.0.0",
        "status": "online",
        "docs_url": "/docs",
        "openapi_url": "/openapi.json"
    }
