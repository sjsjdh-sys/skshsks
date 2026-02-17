"""
agents/validator.py - Validator Agent Node (Skeptical Auditor)

The Validator is a Prosecutor. Its job is to find reasons why a Researcher's
DraftFinding is a FALSE POSITIVE. Only if it cannot be disproved does it
confirm the finding as a real vulnerability.

Key checks:
  - Is there input validation/sanitization applied before the sink?
  - Is the function actually reachable from user-controlled input?
  - Is the dangerous function call using hardcoded values only?
  - Are there framework-level protections (parameterized queries, CSP, etc.)?
  - Is this test code or dead code?
"""

from __future__ import annotations

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import HumanMessage, SystemMessage

from core.schema import (
    AuditState,
    ConfirmedFinding,
    DraftFinding,
    FindingStatus,
    RejectedFinding,
    Severity,
    ValidationTask,
)
from core.state_manager import StateManager
from core.vector_db import VectorEngine
from tools.file_utils import read_file
from tools.scanner_utils import query_code

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sanitizer / Mitigation Pattern Registry
# ---------------------------------------------------------------------------

# Patterns that suggest a vulnerability is mitigated
SANITIZER_PATTERNS = [
    # SQL injection mitigations
    r"parameterized",
    r"prepared\s+statement",
    r"\.filter\(",  # Django ORM
    r"sqlalchemy.*filter",
    r"escape\(",
    r"quote\(",
    r"sanitize\(",
    # Command injection mitigations
    r"shlex\.quote",
    r"shlex\.split",
    r"pipes\.quote",
    # Input validation
    r"validate\(",
    r"is_valid\(",
    r"wtforms",
    r"pydantic",
    r"marshmallow",
    r"cerberus",
    r"jsonschema",
    # Template mitigations
    r"autoescape",
    r"escape\|",  # Jinja2 filter
    r"markupsafe",
    # Deserialization safeguards
    r"yaml\.safe_load",
    r"json\.loads",  # JSON instead of pickle
    # Auth/authz
    r"@login_required",
    r"@permission_required",
    r"@requires_auth",
    r"is_authenticated",
    r"has_permission",
    # Generic guards
    r"allowlist",
    r"whitelist",
    r"ALLOWED_",
    r"VALID_",
]

# Patterns that suggest code is not user-facing
DEAD_CODE_PATTERNS = [
    r"# deprecated",
    r"# unused",
    r"raise\s+NotImplementedError",
    r"pass\s*$",
    r"\.test_",
    r"def test_",
]

TEST_FILE_PATTERNS = [
    "/test",
    "/tests/",
    "_test.py",
    "test_.py",
    "/fixtures/",
    "/mock",
    "conftest",
]


# ---------------------------------------------------------------------------
# Validator Persona
# ---------------------------------------------------------------------------

VALIDATOR_SYSTEM_PROMPT = """You are a Skeptical Security Auditor — a Prosecutor whose job is to find REASONS why a reported vulnerability is a FALSE POSITIVE.

Before confirming any finding, you MUST rigorously check:

1. **Sanitization Check**: Is there any input validation, escaping, or parameterization applied BEFORE the sink?
   - Look for: validate(), sanitize(), escape(), shlex.quote(), parameterized queries, ORM filters

2. **Reachability Check**: Is the vulnerable function actually reachable from user-controlled input?
   - Dead code? Only called internally with hardcoded values? Unreachable routes?

3. **Framework Protection Check**: Does the framework provide automatic protection?
   - Django ORM parameterizes by default; raw() needs extra scrutiny
   - Jinja2 autoescapes by default; mark_safe() or Markup() bypasses this
   - Flask-WTF provides CSRF protection

4. **Hardcoded Value Check**: Is the dangerous function call using ONLY hardcoded/constant values?
   - subprocess.run(["ls", "-la"]) — NOT vulnerable
   - subprocess.run(user_input) — VULNERABLE

5. **Test/Dead Code Check**: Is this in test fixtures, example code, or dead code paths?

Your verdict options:
- **CONFIRM**: Clear taint path, no sanitization, definitely reachable → Real vulnerability
- **REJECT**: Found sanitization, hardcoded values, or unreachable code → False Positive

Be brutal. Security teams are overwhelmed with false positives. Reject anything you're not highly confident in.

Respond ONLY with a valid JSON object:
{
  "verdict": "CONFIRM" | "REJECT",
  "confidence": 0.0-1.0,
  "validator_notes": "Detailed reasoning",
  "false_positive_reason": "If REJECT: specific reason why it's a false positive",
  "confirmed_taint_path": ["step 1", "step 2"] // if CONFIRM
  "cwe_id": "CWE-XXX",  // if CONFIRM
  "remediation": "Specific fix recommendation",  // if CONFIRM
  "severity_adjustment": null  // or "CRITICAL"|"HIGH"|"MEDIUM"|"LOW" if you disagree
}
"""


def _build_validator_prompt(
    task: ValidationTask,
    sanitizer_hits: List[str],
) -> str:
    """Build the validator's analysis prompt."""
    draft = task.draft_finding

    # Truncate source code for token management
    source_lines = task.source_code.splitlines()
    if len(source_lines) > 300:
        # Show region around the finding's location
        focus_line = draft.location.start_line
        start = max(0, focus_line - 50)
        end = min(len(source_lines), focus_line + 50)
        source_excerpt = "\n".join(source_lines[start:end])
        source_excerpt = f"# [Lines {start+1}-{end} shown]\n{source_excerpt}"
    else:
        source_excerpt = task.source_code

    return f"""## Validation Task
- Task ID: {task.task_id}
- File: `{draft.location.file_path}`

## Draft Finding to Validate
```json
{json.dumps({
        "title": draft.title,
        "severity": draft.severity,
        "vulnerability_type": draft.vulnerability_type,
        "location": draft.location.model_dump(),
        "taint_path": draft.taint_path,
        "researcher_confidence": draft.researcher_confidence,
        "evidence": draft.evidence,
    }, indent=2)}
```

## Source Code (context around finding)
```python
{source_excerpt}
```

## Sanitizer / Mitigation Search Results (from vector index)
{chr(10).join(sanitizer_hits[:3]) if sanitizer_hits else "No sanitizer patterns found near this code."}

## Your Prosecution Checklist
1. Is there sanitization/validation BEFORE the sink identified in the taint path?
2. Is the vulnerable code actually reachable from an external user request?
3. Are the values passed to the sink hardcoded or user-controlled?
4. Does the framework provide automatic protection the researcher missed?
5. Is this test code or dead code?

Respond with a JSON verdict object only.
"""


# ---------------------------------------------------------------------------
# Validator Node Function
# ---------------------------------------------------------------------------


def validator_node(
    state: AuditState,
    engine: VectorEngine,
    state_manager: StateManager,
) -> AuditState:
    """
    LangGraph node function for the Validator.

    Receives a ValidationTask (via state._pending_validation), scrutinizes
    the DraftFinding, and either confirms or rejects it.
    """
    state.current_phase = "VALIDATOR"

    # Retrieve the pending validation task
    task: Optional[ValidationTask] = state.__dict__.get("_pending_validation")
    if task is None:
        logger.error("Validator called but no _pending_validation in state!")
        state.next_node = "supervisor"
        return state

    draft = task.draft_finding
    logger.info(
        "Validator reviewing finding '%s' [%s] in %s",
        draft.title,
        draft.severity,
        draft.location.file_path,
    )

    # 1. Check if this is a test file (auto-reject)
    file_path = draft.location.file_path
    if _is_test_file(file_path):
        logger.info("Auto-rejecting: finding is in a test file: %s", file_path)
        rejected = RejectedFinding(
            finding_id=draft.finding_id,
            task_id=draft.task_id,
            title=draft.title,
            reason="Finding is in a test/fixture file — not production code",
        )
        state = state_manager.merge_findings(state, new_rejected=rejected)
        state_manager.save(state)
        state.__dict__.pop("_pending_validation", None)
        state.next_node = "supervisor"
        return state

    # 2. Search for sanitizer patterns near this code
    sanitizer_hits: List[str] = []
    try:
        sanitizer_query = (
            f"sanitize validate escape parameterize "
            f"{draft.vulnerability_type} {draft.location.function_name or ''}"
        )
        sanitizer_hits = query_code(
            engine=engine,
            query=sanitizer_query,
            n_results=3,
            file_filter=file_path,
        )
    except Exception as e:
        state.add_error("Validator sanitizer search", e)

    # 3. Pre-screen: check for obvious sanitizer patterns in the source
    pre_screen_result = _prescreen_source(task.source_code, draft)

    if pre_screen_result:
        logger.info("Pre-screen auto-rejected '%s': %s", draft.title, pre_screen_result)
        rejected = RejectedFinding(
            finding_id=draft.finding_id,
            task_id=draft.task_id,
            title=draft.title,
            reason=f"[Pre-screen] {pre_screen_result}",
        )
        state = state_manager.merge_findings(state, new_rejected=rejected)
        state_manager.save(state)
        state.__dict__.pop("_pending_validation", None)
        state.next_node = "supervisor"
        return state

    # 4. Run the LLM for full validation
    verdict = _run_validator_llm(task=task, sanitizer_hits=sanitizer_hits)

    if verdict.get("verdict") == "CONFIRM":
        # Adjust severity if validator disagrees
        final_severity = draft.severity
        adj = verdict.get("severity_adjustment")
        if adj and adj in [s.value for s in Severity]:
            final_severity = adj
            logger.info(
                "Validator adjusted severity: %s → %s", draft.severity, final_severity
            )

        confirmed = ConfirmedFinding(
            finding_id=draft.finding_id,
            task_id=draft.task_id,
            title=draft.title,
            description=draft.description,
            severity=final_severity,
            vulnerability_type=draft.vulnerability_type,
            location=draft.location,
            taint_path=verdict.get("confirmed_taint_path", draft.taint_path),
            evidence=draft.evidence,
            validator_notes=verdict.get("validator_notes", ""),
            cwe_id=verdict.get("cwe_id"),
            remediation=verdict.get("remediation", ""),
        )

        state = state_manager.merge_findings(state, new_confirmed=confirmed)
        logger.info(
            "✓ CONFIRMED [%s]: %s — %s",
            confirmed.severity,
            confirmed.title,
            confirmed.cwe_id or "no CWE",
        )

    else:  # REJECT
        reason = verdict.get("false_positive_reason") or verdict.get(
            "validator_notes", "Rejected by validator"
        )
        rejected = RejectedFinding(
            finding_id=draft.finding_id,
            task_id=draft.task_id,
            title=draft.title,
            reason=reason,
        )
        state = state_manager.merge_findings(state, new_rejected=rejected)
        logger.info("✗ REJECTED (False Positive): %s — %s", draft.title, reason)

    # Save state after each validation
    state_manager.save(state)

    # Clean up
    state.__dict__.pop("_pending_validation", None)
    state.next_node = "supervisor"
    return state


def _is_test_file(file_path: str) -> bool:
    """Heuristic check: is this path a test/fixture file?"""
    path_lower = file_path.lower()
    return any(pattern in path_lower for pattern in TEST_FILE_PATTERNS)


def _prescreen_source(source: str, draft: DraftFinding) -> Optional[str]:
    """
    Quick regex-based pre-screening for obvious false positives.
    Returns a reason string if it's a false positive, None if uncertain.
    """
    # Check for sanitizer patterns in the vicinity of the finding
    lines = source.splitlines()
    focus_start = max(0, draft.location.start_line - 10)
    focus_end = min(len(lines), draft.location.end_line + 10)
    focus_region = "\n".join(lines[focus_start:focus_end])

    for pattern in SANITIZER_PATTERNS:
        if re.search(pattern, focus_region, re.IGNORECASE):
            return f"Sanitizer pattern '{pattern}' found near the vulnerable code"

    # Check for dead code markers
    for pattern in DEAD_CODE_PATTERNS:
        if re.search(pattern, focus_region, re.IGNORECASE | re.MULTILINE):
            return f"Dead/unreachable code marker found: '{pattern}'"

    return None


def _run_validator_llm(
    task: ValidationTask,
    sanitizer_hits: List[str],
) -> Dict[str, Any]:
    """Invoke the Validator LLM and return parsed verdict dict."""
    model_name = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5-20250929")
    llm = ChatAnthropic(model=model_name, max_tokens=1024, temperature=0)

    prompt = _build_validator_prompt(task=task, sanitizer_hits=sanitizer_hits)

    try:
        response = llm.invoke(
            [
                SystemMessage(content=VALIDATOR_SYSTEM_PROMPT),
                HumanMessage(content=prompt),
            ]
        )
        raw = response.content

        if isinstance(raw, str):
            raw = raw.strip()
            if raw.startswith("```"):
                lines = raw.splitlines()
                raw = "\n".join(
                    lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
                )

        return json.loads(raw)

    except json.JSONDecodeError as e:
        logger.error("Validator LLM returned invalid JSON: %s", e)
        # Default to rejection when unsure (conservative approach for FP prevention)
        return {
            "verdict": "REJECT",
            "false_positive_reason": f"Validator LLM returned invalid JSON: {e}",
            "validator_notes": "Could not parse validator response",
            "confidence": 0.0,
        }

    except Exception as e:
        logger.error("Validator LLM error: %s", e)
        return {
            "verdict": "REJECT",
            "false_positive_reason": f"Validator error: {e}",
            "validator_notes": "Validator encountered an error",
            "confidence": 0.0,
        }
