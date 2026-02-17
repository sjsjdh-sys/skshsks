from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from tool_api.dependencies import DB
from tool_api.services import toolService

router = APIRouter(prefix="/tool", tags=["tool"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class RunTool(BaseModel):
    uuid: str
    filepath: str

class Status(BaseModel):
    PENDING = "pending"
    BUILDING_TREE = "building_tree"
    BUILDING_DATABASE = "building_database"
    EXAMINING_FILES = "examining_files"
    EXAMINING_DIRECTORIES = "examining_directories"
    UPDATING_DATABASE = "updating_database"
    GENERATING_REPORTS = "generating_reports"
    COMPLETED = "complete"


class ToolResponse(BaseModel):
    uuid: str
    filepath: str
    status: str


@router.post("", response_model=ToolResponse, status_code=201)
async def run_tool(body: RunTool, db: DB) -> ToolResponse:
    try:
        result = await toolService.run_tool(uuid = body.uuid, fp = body.filepath ,  db =  db)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return ToolResponse(**result)
