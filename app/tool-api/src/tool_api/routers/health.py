from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from tool_api.services import healthService
from db_connector import DBConnector


router = APIRouter(prefix="/health", tags=["health"])


class HealthResponse(BaseModel):
    status: str
    neo4j: str

@router.get("", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Return API liveness and Neo4j connectivity status."""
    try:
        neo4j_status =  await healthService.heatlh_check()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Neo4j unavailable: {exc}") from exc
    return HealthResponse(status="ok", neo4j=neo4j_status)
