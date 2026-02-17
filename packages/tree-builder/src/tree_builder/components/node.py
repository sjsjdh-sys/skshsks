from pydantic import BaseModel, Field
from typing import Optional , List , Literal
from enum import StrEnum

class NodeType(StrEnum):
    FILE = "file"
    DIRECTORY = "directory"
    REPORT = "report"

class NodeStatus(StrEnum):
    BUILT      = "built"
    CREATED    = "created"
    COMPLETED  = "completed"
    PROCESSING = "processing"
    FAILED     = "failed"


class Node(BaseModel):
    fp: str
    fn: str
    node_type: NodeType | None  = None
    status:NodeStatus
    depth: int
    parent: str | None = None
    children: List[str] = Field(default_factory=list)
    artifacts: List[str] = Field(default_factory=list)
    temperature: float | None = Field(default=None, ge=0.0, le=2.0)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    content: str | None = None
    model: str | None = None

