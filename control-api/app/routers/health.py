from fastapi import APIRouter, HTTPException

from app.database import get_connection
from app.schemas import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health/live", response_model=HealthResponse)
def health_live():
    return {"status": "alive"}


@router.get("/health/ready", response_model=HealthResponse)
def health_ready():
    try:
        conn = get_connection()
        try:
            conn.execute("SELECT 1").fetchone()
        finally:
            conn.close()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=503, detail="Database is not ready") from exc
    return {"status": "ready"}
