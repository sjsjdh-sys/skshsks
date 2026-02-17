"""
agents/researcher.py - Researcher Agent Node

The Researcher is a Deep-Dive Analyst. It receives a ResearchTask from the
Supervisor and performs detailed taint path analysis to find the path from
input sources to dangerous execution sinks.

Stateless: Only receives what it needs for this specific task.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from core.schema import (
    AuditState,
    CodeLocation,
    DraftFinding,
    ResearchTask,
    Severity,
)
from core.vector_db import VectorEngine
from tools.file_utils import read_file, read_function
from tools.scanner_utils import query_code

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Researcher Persona
# ---------------------------------------------------------------------------

RESEARCHER_SYSTEM_PROMPT = """You are a Deep-Dive Security Analyst — a specialist in taint analysis and attack path tracing.

Your mission: Find the complete "Taint Path" from user-controlled input (sources) to dangerous execution sinks.

Sources (inputs you must track):
- HTTP request parameters: request.args, request.form, request.json, request.data
- Function arguments from routes/views (especially if unsanitized)
- Environment variables used insecurely
- File uploads, cookies, headers

Sinks (dangerous endpoints to reach):
- os.system(), subprocess, popen() — Command Injection
- eval(), exec(), compile() — Code Injection  
- SQL execute() with f-strings or % formatting — SQL Injection
- pickle.loads(), yaml.load() — Deserialization
- open() with user paths — Path Traversal
- render_template_string() — SSTI
- Any output without escaping — XSS

Analysis process:
1. Read the file and focus function
2. Identify all taint sources in the function/file
3. Trace the data flow step by step
4. Identify if tainted data reaches a sink WITHOUT sanitization
5. If found: report a DraftFinding with the full taint path

Be SPECIFIC. Include line numbers, variable names, and actual code paths.
Rate confidence honestly: 1.0 = certain, 0.5 = likely, 0.2 = possible.

CRITICAL: Your response must be a single valid JSON object only.
All code snippets in JSON values MUST use markdown code fences:
  {"evidence": "```python\\ncode here\\n```"}
Never include raw code outside of markdown fences in JSON string values.
"""


def _build_researcher_prompt(
    task: ResearchTask,
    file_source: str,
    function_source: Optional[str],
    semantic_context: List[str],
) -> str:
    """Build the researcher's analysis prompt."""

    semgrep_hits_json = []
    for hit in task.semgrep_hits:
        semgrep_hits_json.append(
            {
                "rule": hit.rule_id,
                "message": hit.message,
                "severity": hit.severity,
                "line": hit.start_line,
                "snippet": hit.snippet,
            }
        )

    # Truncate file source to avoid hitting token limits
    file_lines = file_source.splitlines()
    if len(file_lines) > 200:
        file_source_display = "\n".join(file_lines[:200])
        file_source_display += f"\n... [{len(file_lines) - 200} more lines truncated]"
    else:
        file_source_display = file_source

    function_section = ""
    if function_source:
        function_section = f"""
## Target Function Source
```python
{function_source}
```
"""

    return f"""## Research Task
- Task ID: {task.task_id}
- File: `{task.file_path}`
- Focus Area: {task.focus}
- Priority: {task.priority_hint}

## Pre-Scan Results (Semgrep)
{json.dumps(semgrep_hits_json, indent=2) if semgrep_hits_json else "No semgrep matches."}

{function_section}

## Full File Source (first 200 lines)
```python
{file_source_display}
```

## Related Code from Vector Index
{chr(10).join(semantic_context[:3]) if semantic_context else "No additional context."}

## Your Task
Perform taint analysis. Find if user-controlled data flows to a dangerous sink.

If you find a vulnerability, respond with this JSON schema:
{{
  "finding_id": "auto",
  "task_id": "{task.task_id}",
  "title": "Short descriptive title (e.g. 'SQL Injection in get_user_data()')",
  "description": "Detailed explanation of the vulnerability",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "vulnerability_type": "SQL Injection|Command Injection|Code Injection|etc.",
  "location": {{
    "file_path": "{task.file_path}",
    "start_line": 0,
    "end_line": 0,
    "function_name": "function_name"
  }},
  "taint_path": [
    "1. Source: request.args['user_id'] at line N",
    "2. Passed to: query_db(user_id) at line N",
    "3. Sink: cursor.execute(f'SELECT * FROM users WHERE id={{user_id}}') at line N"
  ],
  "evidence": "```python\\nactual vulnerable code snippet here\\n```",
  "semgrep_matches": [],
  "researcher_confidence": 0.85
}}

If NO vulnerability found, respond with:
{{"no_finding": true, "reason": "explanation of why no vulnerability exists"}}
"""


# ---------------------------------------------------------------------------
# Researcher Node Function
# ---------------------------------------------------------------------------


def researcher_node(state: AuditState, engine: VectorEngine) -> AuditState:
    """
    LangGraph node function for the Researcher.

    Receives a ResearchTask from state, performs deep analysis,
    and produces a DraftFinding (or nothing if no issue found).
    """
    state.current_phase = "RESEARCHER"

    task = state.current_research_task
    if not task:
        logger.error("Researcher called but no current_research_task in state!")
        state.next_node = "supervisor"
        return state

    logger.info(
        "Researcher analyzing task %s: %s (focus: %s)",
        task.task_id,
        task.file_path,
        task.focus,
    )

    # 1. Read the full file source
    file_source = read_file(task.file_path) or ""
    if not file_source:
        logger.warning("Could not read source for %s", task.file_path)
        state.current_research_task = None
        state.next_node = "supervisor"
        return state

    # 2. Try to read the specific function mentioned in focus
    function_source: Optional[str] = None
    focus_words = task.focus.split()
    for word in focus_words:
        # Strip common characters that might not be function names
        candidate = word.strip("():,.'\"")
        if candidate and candidate[0].isalpha():
            function_source = read_function(task.file_path, candidate)
            if function_source:
                logger.debug("Loaded function source for '%s'", candidate)
                break

    # 3. Semantic search for related dangerous patterns
    semantic_context: List[str] = []
    try:
        semantic_context = query_code(
            engine=engine,
            query=f"taint path user input {task.focus} security vulnerability",
            n_results=3,
            file_filter=task.file_path,
        )
    except Exception as e:
        state.add_error(f"Researcher vector query for {task.file_path}", e)

    # 4. Run the LLM analysis
    draft = _run_researcher_llm(
        task=task,
        file_source=file_source,
        function_source=function_source,
        semantic_context=semantic_context,
    )

    if draft:
        logger.info(
            "Researcher found [%s]: %s (confidence=%.2f)",
            draft.severity,
            draft.title,
            draft.researcher_confidence,
        )
        # Store draft for supervisor → validator routing
        state.current_draft = draft
        state.draft_findings.append(draft)
        state.current_research_task = None
        state.next_node = "supervisor"  # Supervisor will route to Validator
    else:
        logger.info("Researcher: no finding for %s", task.file_path)
        state.current_research_task = None
        state.next_node = "supervisor"

    return state


def _run_researcher_llm(
    task: ResearchTask,
    file_source: str,
    function_source: Optional[str],
    semantic_context: List[str],
) -> Optional[DraftFinding]:
    """Invoke the Researcher LLM and parse the result into a DraftFinding."""
    model_name = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")
    llm = ChatAnthropic(model=model_name, max_tokens=2048, temperature=0)

    prompt = _build_researcher_prompt(
        task=task,
        file_source=file_source,
        function_source=function_source,
        semantic_context=semantic_context,
    )

    try:
        response = llm.invoke(
            [
                SystemMessage(content=RESEARCHER_SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ]
        )
        raw = response.content

        if isinstance(raw, str):
            raw = raw.strip()
            # Strip markdown fences
            if raw.startswith("```"):
                lines = raw.splitlines()
                raw = "\n".join(
                    lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
                )

        data = json.loads(raw)

        # Check for explicit no-finding response
        if data.get("no_finding"):
            logger.debug("Researcher: explicit no-finding: %s", data.get("reason", ""))
            return None

        # Normalize finding_id
        if data.get("finding_id") == "auto" or not data.get("finding_id"):
            import uuid

            data["finding_id"] = str(uuid.uuid4())[:8]

        # Ensure semgrep_matches is formatted correctly
        if "semgrep_matches" not in data:
            data["semgrep_matches"] = [m.model_dump() for m in task.semgrep_hits[:3]]

        draft = DraftFinding.model_validate(data)
        return draft

    except json.JSONDecodeError as e:
        logger.error("Researcher LLM returned invalid JSON: %s\nRaw: %s", e, raw[:300])  # type: ignore[possibly-undefined]
        return None

    except Exception as e:
        logger.error("Researcher LLM error: %s", e)
        return None
