"""
agents/supervisor.py - Supervisor Agent Node

The Supervisor is the orchestrator. It:
  1. Reads the file tree and initializes the scan queue
  2. Prioritizes high-value targets (APIs, DB sinks, auth flows)
  3. Delegates ResearchTasks to the Researcher
  4. Collects DraftFindings and delegates ValidationTasks to the Validator
  5. Maintains and persists the global AuditState
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from core.schema import (
    AgentDecision,
    AuditState,
    DraftFinding,
    ResearchTask,
    Severity,
    SemgrepMatch,
    SupervisorDecision,
    TaskType,
    ValidationTask,
)
from core.vector_db import VectorEngine
from tools.file_utils import list_files, read_file
from tools.scanner_utils import query_code, semgrep_wrapper

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Priority Scoring
# ---------------------------------------------------------------------------

# Keywords that indicate high-priority targets for security analysis
HIGH_PRIORITY_KEYWORDS = {
    # Entry points
    "view",
    "route",
    "controller",
    "endpoint",
    "api",
    "handler",
    "webhook",
    "middleware",
    "request",
    "response",
    "dispatch",
    # Auth
    "auth",
    "login",
    "register",
    "token",
    "permission",
    "oauth",
    "session",
    "password",
    "credential",
    "secret",
    "key",
    # Data sinks
    "query",
    "execute",
    "cursor",
    "model",
    "orm",
    "database",
    "db",
    "sql",
    "mongo",
    "redis",
    "cache",
    # File/system
    "upload",
    "download",
    "file",
    "path",
    "shell",
    "subprocess",
    # Output
    "render",
    "template",
    "serialize",
    "deserialize",
    "pickle",
}


def _priority_score(file_path: str) -> int:
    """
    Score a file path by its likely security importance.
    Higher = more important to audit first.
    """
    path_lower = file_path.lower()
    score = 0

    for keyword in HIGH_PRIORITY_KEYWORDS:
        if keyword in path_lower:
            score += 2

    # Boost paths in common high-value directories
    if any(d in path_lower for d in ["/views/", "/api/", "/auth/", "/controllers/"]):
        score += 5
    if any(d in path_lower for d in ["/utils/", "/helpers/", "/lib/"]):
        score += 1

    return score


def prioritize_files(files: List[str]) -> List[str]:
    """Sort files by security priority (highest first)."""
    scored = [(f, _priority_score(f)) for f in files]
    scored.sort(key=lambda x: x[1], reverse=True)
    return [f for f, _ in scored]


# ---------------------------------------------------------------------------
# Supervisor LLM Prompt
# ---------------------------------------------------------------------------

SUPERVISOR_SYSTEM_PROMPT = """You are a pragmatic Security Lead conducting a comprehensive security audit.

Your core responsibilities:
1. Prioritize analysis of entry points: REST APIs, web controllers, WebSocket handlers
2. Focus on data flow into database sinks (ORM queries, raw SQL)
3. Identify authentication/authorization weaknesses first
4. Delegate deep analysis tasks efficiently

When evaluating scan results for a file, decide:
- DELEGATE_RESEARCH: If semgrep or patterns found suspicious code needing deep taint analysis
- SKIP: If the file appears to be pure configuration, documentation, or test fixtures
- COMPLETE: If all files have been processed

For each delegation, specify EXACTLY:
- The file to analyze
- The specific function or area to focus on  
- Why this is a priority (entry point? DB sink? auth?)

Respond ONLY with a valid JSON object matching the SupervisorDecision schema.
Be decisive — don't over-explain. Think like a CISO reviewing a penetration test scope.

Severity priorities (highest risk first):
1. Remote code execution / command injection (CRITICAL)
2. SQL injection with user input (HIGH)
3. Authentication bypass / broken access control (HIGH)
4. Insecure deserialization (CRITICAL)
5. Sensitive data exposure (MEDIUM-HIGH)
6. Information disclosure via errors (LOW-MEDIUM)
"""


def _build_supervisor_prompt(
    state: AuditState,
    file_path: str,
    semgrep_results: List[SemgrepMatch],
    semantic_hits: List[str],
) -> str:
    """Build the supervisor's analysis prompt for a specific file."""
    semgrep_summary = []
    for match in semgrep_results[:10]:  # Cap to avoid token overflow
        semgrep_summary.append(
            {
                "rule": match.rule_id,
                "message": match.message,
                "severity": match.severity,
                "line": match.start_line,
                "snippet": match.snippet,
            }
        )

    prompt = f"""## Audit Status
- Session: {state.session_id}
- Target: {state.target_repo}
- Progress: {len(state.scanned_files)}/{len(state.all_files)} files scanned
- Confirmed findings: {len(state.confirmed_findings)}
- Files remaining: {len(state.pending_files)}

## Current File Under Review
`{file_path}`

## Semgrep Scan Results ({len(semgrep_results)} matches)
{json.dumps(semgrep_summary, indent=2)}

## Semantic Code Search Hits (from vector index)
{chr(10).join(semantic_hits[:3]) if semantic_hits else "No semantic matches found."}

## Your Task
Based on the above, decide what to do with this file.
If DELEGATE_RESEARCH, identify the most critical function/area to investigate.

Respond with a JSON object:
{{
  "decision": "DELEGATE_RESEARCH" | "SKIP" | "COMPLETE",
  "reasoning": "...",
  "next_file": null,
  "research_task": {{
    "task_id": "auto",
    "task_type": "SEMANTIC_AUDIT",
    "file_path": "{file_path}",
    "focus": "specific function or vulnerability type to investigate",
    "semgrep_hits": [...relevant matches...],
    "context_snippets": [],
    "priority_hint": "entry_point|database|auth|general"
  }}
}}
"""
    return prompt


# ---------------------------------------------------------------------------
# Supervisor Node Function
# ---------------------------------------------------------------------------


def supervisor_node(state: AuditState, engine: VectorEngine) -> AuditState:
    """
    LangGraph node function for the Supervisor.

    Reads the next pending file, runs initial scans, and decides
    whether to delegate research or skip.
    """
    state.iteration_count += 1
    state.current_phase = "SUPERVISOR"

    # Check iteration limit
    if state.iteration_count >= state.max_iterations:
        logger.warning("Max iterations (%d) reached. Finalizing.", state.max_iterations)
        state.next_node = "END"
        return state

    # --- Handle incoming draft finding (from Researcher) ---
    if state.current_draft is not None:
        draft = state.current_draft
        state.current_draft = None

        logger.info(
            "Supervisor received DraftFinding '%s' — routing to Validator",
            draft.title,
        )

        # Get the source code for validation context
        source = read_file(draft.location.file_path) or ""

        # Get related sanitizer snippets from vector DB
        related = query_code(
            engine=engine,
            query=f"sanitizer validation input checking {draft.vulnerability_type}",
            n_results=3,
            file_filter=draft.location.file_path,
        )

        validation_task = ValidationTask(
            task_id=draft.task_id,
            draft_finding=draft,
            source_code=source,
            related_snippets=related,
        )

        # Store for pickup by validator
        state.current_research_task = None  # Clear research task
        # We use a temp attribute trick via dict since pydantic is immutable-ish
        # In practice, we store the validation task in state for the validator node
        state.__dict__["_pending_validation"] = validation_task
        state.next_node = "validator"
        return state

    # --- Check if there are any pending files ---
    if not state.pending_files:
        logger.info("All files processed. Audit complete.")
        state.next_node = "END"
        state.current_phase = "COMPLETE"
        return state

    # --- Pick the next file to analyze ---
    file_path = state.pending_files[0]
    logger.info("Supervisor processing: %s", file_path)

    # 1. Run Semgrep (or AST fallback) on the file
    semgrep_results: List[SemgrepMatch] = []
    try:
        semgrep_results = semgrep_wrapper(file_path)
    except Exception as e:
        state.add_error(f"Semgrep scan of {file_path}", e)
        logger.error("Semgrep failed for %s: %s", file_path, e)

    # 2. Quick semantic query for suspicious patterns
    semantic_hits: List[str] = []
    try:
        semantic_hits = query_code(
            engine=engine,
            query="dangerous function user input execution database query",
            n_results=3,
            file_filter=file_path,
        )
    except Exception as e:
        state.add_error(f"Vector query for {file_path}", e)

    # 3. If no findings at all, skip this file
    if not semgrep_results and not semantic_hits:
        logger.info("No issues found in %s — skipping.", file_path)
        state.pending_files.pop(0)
        state.scanned_files.append(file_path)
        state.next_node = "supervisor"  # Loop back
        return state

    # 4. Ask the LLM to make a delegation decision
    decision = _run_supervisor_llm(state, file_path, semgrep_results, semantic_hits)

    if decision.decision == AgentDecision.DELEGATE_RESEARCH:
        research_task = decision.research_task
        if research_task:
            # Ensure task has correct file path
            research_task.file_path = file_path
            state.current_research_task = research_task
            state.pending_files.pop(0)
            state.scanned_files.append(file_path)
            state.next_node = "researcher"
            logger.info(
                "Delegating research task '%s' to Researcher (focus: %s)",
                research_task.task_id,
                research_task.focus,
            )
        else:
            # LLM said delegate but provided no task — create one automatically
            state.current_research_task = _auto_research_task(
                file_path, semgrep_results
            )
            state.pending_files.pop(0)
            state.scanned_files.append(file_path)
            state.next_node = "researcher"

    elif decision.decision == AgentDecision.SKIP:
        logger.info("Supervisor decided to SKIP %s: %s", file_path, decision.reasoning)
        state.pending_files.pop(0)
        state.scanned_files.append(file_path)
        state.next_node = "supervisor"

    elif decision.decision == AgentDecision.COMPLETE:
        logger.info("Supervisor declared audit COMPLETE.")
        state.pending_files.pop(0)
        state.scanned_files.append(file_path)
        state.next_node = "END"

    else:
        # Fallback: skip
        state.pending_files.pop(0)
        state.scanned_files.append(file_path)
        state.next_node = "supervisor"

    return state


def _run_supervisor_llm(
    state: AuditState,
    file_path: str,
    semgrep_results: List[SemgrepMatch],
    semantic_hits: List[str],
) -> SupervisorDecision:
    """Invoke the Supervisor LLM to make a routing decision."""
    model_name = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")
    llm = ChatAnthropic(model=model_name, max_tokens=1024, temperature=0)

    prompt = _build_supervisor_prompt(state, file_path, semgrep_results, semantic_hits)

    try:
        response = llm.invoke(
            [
                SystemMessage(content=SUPERVISOR_SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ]
        )
        raw = response.content

        # Strip markdown fences if present
        if isinstance(raw, str):
            raw = raw.strip()
            if raw.startswith("```"):
                lines = raw.splitlines()
                raw = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        data = json.loads(raw)

        # Handle auto task_id
        if "research_task" in data and data["research_task"]:
            rt = data["research_task"]
            if rt.get("task_id") == "auto" or not rt.get("task_id"):
                import uuid

                rt["task_id"] = str(uuid.uuid4())[:8]
            # Ensure required fields
            if not rt.get("file_path"):
                rt["file_path"] = file_path

        return SupervisorDecision.model_validate(data)

    except json.JSONDecodeError as e:
        logger.error("Supervisor LLM returned invalid JSON: %s", e)
        # Default to researching if semgrep found issues
        if semgrep_results:
            return SupervisorDecision(
                decision=AgentDecision.DELEGATE_RESEARCH,
                reasoning="Semgrep found issues; auto-delegating research.",
                research_task=_auto_research_task(file_path, semgrep_results),
            )
        return SupervisorDecision(
            decision=AgentDecision.SKIP,
            reasoning="LLM error; no semgrep issues found.",
        )

    except Exception as e:
        logger.error("Supervisor LLM error: %s", e)
        state.add_error("Supervisor LLM", e)
        return SupervisorDecision(
            decision=AgentDecision.SKIP,
            reasoning=f"LLM error: {e}",
        )


def _auto_research_task(
    file_path: str,
    semgrep_results: List[SemgrepMatch],
) -> ResearchTask:
    """Create a fallback ResearchTask when the LLM doesn't provide one."""
    import uuid

    focus = "all functions with user input handling"
    if semgrep_results:
        top = semgrep_results[0]
        focus = f"line {top.start_line}: {top.message}"

    return ResearchTask(
        task_id=str(uuid.uuid4())[:8],
        task_type=TaskType.STATIC_SCAN,
        file_path=file_path,
        focus=focus,
        semgrep_hits=semgrep_results[:5],
        priority_hint="general",
    )
