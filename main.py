"""
core/schema.py - Pydantic Models for test Security Auditor
All inter-agent communication and data structures are defined here.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, Enum):
    DRAFT = "DRAFT"
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class TaskType(str, Enum):
    STATIC_SCAN = "STATIC_SCAN"
    SEMANTIC_AUDIT = "SEMANTIC_AUDIT"
    TAINT_ANALYSIS = "TAINT_ANALYSIS"


class AgentDecision(str, Enum):
    CONTINUE = "CONTINUE"
    DELEGATE_RESEARCH = "DELEGATE_RESEARCH"
    DELEGATE_VALIDATION = "DELEGATE_VALIDATION"
    COMPLETE = "COMPLETE"
    SKIP = "SKIP"


# ---------------------------------------------------------------------------
# Core Data Models
# ---------------------------------------------------------------------------


class CodeLocation(BaseModel):
    """Precise location of a code element."""

    file_path: str
    start_line: int
    end_line: int
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    signature: Optional[str] = None


class SemgrepMatch(BaseModel):
    """Raw match from Semgrep scan output."""

    rule_id: str
    message: str
    severity: str
    path: str
    start_line: int
    end_line: int
    snippet: str  # markdown-fenced code block
    extra: Dict[str, Any] = Field(default_factory=dict)


class DraftFinding(BaseModel):
    """
    Produced by the Researcher node.
    Represents an unconfirmed vulnerability with taint path analysis.
    """

    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    task_id: str
    title: str
    description: str
    severity: Severity
    vulnerability_type: str  # e.g., "SQL Injection", "Command Injection"
    location: CodeLocation
    taint_path: List[str] = Field(
        default_factory=list,
        description="Ordered list of code nodes from source to sink",
    )
    evidence: str = Field(description="Code snippet in markdown code block format")
    semgrep_matches: List[SemgrepMatch] = Field(default_factory=list)
    researcher_confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Researcher's confidence score (0.0 - 1.0)",
    )
    raw_context: Optional[str] = None

    @field_validator("evidence")
    @classmethod
    def evidence_must_be_fenced(cls, v: str) -> str:
        """Evidence snippets must use markdown code fences."""
        stripped = v.strip()
        if not stripped.startswith("```"):
            return f"```python\n{stripped}\n```"
        return v

    model_config = {"use_enum_values": True}


class ConfirmedFinding(BaseModel):
    """
    Produced by the Validator node after confirming a DraftFinding.
    This is the final, auditable output.
    """

    finding_id: str
    task_id: str
    title: str
    description: str
    severity: Severity
    vulnerability_type: str
    location: CodeLocation
    taint_path: List[str]
    evidence: str
    status: FindingStatus = FindingStatus.CONFIRMED
    validator_notes: str = ""
    confirmed_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    cwe_id: Optional[str] = None
    remediation: str = ""

    model_config = {"use_enum_values": True}

    @classmethod
    def from_draft(
        cls,
        draft: DraftFinding,
        validator_notes: str,
        cwe_id: Optional[str] = None,
        remediation: str = "",
    ) -> "ConfirmedFinding":
        return cls(
            finding_id=draft.finding_id,
            task_id=draft.task_id,
            title=draft.title,
            description=draft.description,
            severity=draft.severity,
            vulnerability_type=draft.vulnerability_type,
            location=draft.location,
            taint_path=draft.taint_path,
            evidence=draft.evidence,
            validator_notes=validator_notes,
            cwe_id=cwe_id,
            remediation=remediation,
        )


class RejectedFinding(BaseModel):
    """Record of a finding rejected as False Positive by the Validator."""

    finding_id: str
    task_id: str
    title: str
    reason: str
    rejected_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())


# ---------------------------------------------------------------------------
# Task / Handoff Models
# ---------------------------------------------------------------------------


class ResearchTask(BaseModel):
    """
    Issued by Supervisor → Researcher.
    Minimal context: only what the researcher needs.
    """

    task_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    task_type: TaskType = TaskType.SEMANTIC_AUDIT
    file_path: str
    focus: str = Field(description="Specific function, class, or area to focus on")
    semgrep_hits: List[SemgrepMatch] = Field(default_factory=list)
    context_snippets: List[str] = Field(
        default_factory=list,
        description="Relevant code snippets from vector search",
    )
    priority_hint: str = ""

    model_config = {"use_enum_values": True}


class ValidationTask(BaseModel):
    """
    Issued by Supervisor → Validator.
    Contains the DraftFinding plus original source for cross-checking.
    """

    task_id: str
    draft_finding: DraftFinding
    source_code: str = Field(
        description="Full source of the file containing the finding"
    )
    related_snippets: List[str] = Field(
        default_factory=list,
        description="Vector-search results for sanitizer patterns",
    )


class SupervisorDecision(BaseModel):
    """Output of the Supervisor node's reasoning step."""

    decision: AgentDecision
    reasoning: str
    next_file: Optional[str] = None
    research_task: Optional[ResearchTask] = None
    validation_task: Optional[ValidationTask] = None

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# Global Audit State (LangGraph State)
# ---------------------------------------------------------------------------


class AuditState(BaseModel):
    """
    Global mutable state managed by the Supervisor.
    Passed through the LangGraph state machine.
    """

    # Configuration
    target_repo: str = ""
    session_id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    started_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat())

    # File tracking
    all_files: List[str] = Field(default_factory=list)
    pending_files: List[str] = Field(default_factory=list)
    scanned_files: List[str] = Field(default_factory=list)
    failed_files: List[str] = Field(default_factory=list)

    # Finding pipeline
    draft_findings: List[DraftFinding] = Field(default_factory=list)
    confirmed_findings: List[ConfirmedFinding] = Field(default_factory=list)
    rejected_findings: List[RejectedFinding] = Field(default_factory=list)

    # Current task in-flight
    current_research_task: Optional[ResearchTask] = None
    current_draft: Optional[DraftFinding] = None

    # Flow control
    current_phase: str = "INIT"
    iteration_count: int = 0
    max_iterations: int = 50
    error_log: List[str] = Field(default_factory=list)

    # LangGraph routing signal
    next_node: str = "supervisor"

    model_config = {"use_enum_values": True}

    def add_error(self, context: str, error: Exception) -> None:
        """Append a formatted error to the error log."""
        entry = f"[{datetime.utcnow().isoformat()}] {context}: {type(error).__name__}: {error}"
        self.error_log.append(entry)

    def summary(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_repo": self.target_repo,
            "total_files": len(self.all_files),
            "scanned": len(self.scanned_files),
            "pending": len(self.pending_files),
            "confirmed_findings": len(self.confirmed_findings),
            "rejected_findings": len(self.rejected_findings),
            "draft_findings": len(self.draft_findings),
            "errors": len(self.error_log),
        }
