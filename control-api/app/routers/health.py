from fastapi import APIRouter
from app.schemas import HealthResponse

router = APIRouter(tags=["Health"])

@router.get("/health/live", response_model=HealthResponse)
def health_live():
    return {"status": "alive"}

@router.get("/health/ready", response_model=HealthResponse)
def health_ready():
    return {"status": "ready"}
