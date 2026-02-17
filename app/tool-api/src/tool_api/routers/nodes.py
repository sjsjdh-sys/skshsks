from typing import Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from tool_api.dependencies import DB
from tool_api.services import nodesService

router = APIRouter(prefix="/nodes", tags=["nodes"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class NodeCreate(BaseModel):
    label: str
    properties: dict[str, Any] = {}


class NodeBatchCreate(BaseModel):
    nodes: list[NodeCreate]


class NodeResponse(BaseModel):
    element_id: str | None = None
    labels: list[str]
    properties: dict[str, Any]


class QueryRequest(BaseModel):
    cypher: str
    parameters: dict[str, Any] = {}


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("", response_model=NodeResponse, status_code=201)
async def create_node(body: NodeCreate, db: DB) -> NodeResponse:
    """Create a single node in Neo4j."""
    try:
        result = await nodesService.create_node(body.labels, body.properties, db)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return NodeResponse(**result)


@router.post("/batch", response_model=list[NodeResponse], status_code=201)
async def create_nodes(body: NodeBatchCreate, db: DB) -> list[NodeResponse]:
    """Create multiple nodes in a single transaction."""
    try:
        results =  await nodesService.create_nodes(nodes=body.nodes, db= db)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return [NodeResponse(**r) for r in results]


@router.post("/query", response_model=list[dict[str, Any]])
async def run_query(body: QueryRequest, db: DB) -> list[dict[str, Any]]:
    """Execute a raw Cypher query and return the results."""
    try:
        return await nodesService.run_query(cypher = body.cypher , parmeters = body.parameters, db = db)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/{label}", response_model=list[NodeResponse])
async def get_nodes_by_label(label: str, db: DB) -> list[NodeResponse]:
    """Fetch all nodes with the given label."""
    try:
        results = await nodesService.get_nodes_by_label(label=label, db= db)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return [NodeResponse(**row["n"]) for row in results]
