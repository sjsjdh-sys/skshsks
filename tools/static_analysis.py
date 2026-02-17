"""
tools/scanner_utils.py - Semgrep Wrapper + AST Pattern Scanner

Implements:
 - semgrep_wrapper: Execute semgrep scan and parse results into SemgrepMatch objects
 - ast_pattern_scan: Pure-Python fallback pattern scanner using AST inspection
 - query_code: Semantic search interface wrapping VectorEngine
"""

from __future__ import annotations

import ast
import json
import logging
import os
import re
import subprocess
import textwrap
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.schema import SemgrepMatch, Severity
from core.vector_db import VectorEngine

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Semgrep Configuration
# ---------------------------------------------------------------------------

SEMGREP_TIMEOUT = int(os.getenv("SEMGREP_TIMEOUT", "60"))
SEMGREP_CONFIG = os.getenv("SEMGREP_CONFIG", "auto")

# Default ruleset for security auditing
SECURITY_RULESETS = [
    "p/python",
    "p/owasp-top-ten",
    "p/security-audit",
]


# ---------------------------------------------------------------------------
# Severity Mapping
# ---------------------------------------------------------------------------


def _map_severity(raw: str) -> Severity:
    """Map semgrep severity strings to our Severity enum."""
    mapping = {
        "ERROR": Severity.HIGH,
        "WARNING": Severity.MEDIUM,
        "INFO": Severity.INFO,
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return mapping.get(raw.upper(), Severity.INFO)


# ---------------------------------------------------------------------------
# Semgrep Wrapper Tool
# ---------------------------------------------------------------------------


def semgrep_wrapper(
    file_path: str,
    config: str = SEMGREP_CONFIG,
    additional_configs: Optional[List[str]] = None,
    timeout: int = SEMGREP_TIMEOUT,
) -> List[SemgrepMatch]:
    """
    Execute `semgrep scan --json` on a target file and parse results.

    Args:
        file_path: Path to the Python file to scan.
        config: Semgrep config/ruleset to use (default: 'auto').
        additional_configs: Extra rulesets to run.
        timeout: Maximum seconds to wait for semgrep.

    Returns:
        List of SemgrepMatch objects. Empty list if semgrep unavailable.
    """
    target = Path(file_path)
    if not target.exists():
        logger.warning("semgrep_wrapper: file not found: %s", file_path)
        return []

    # Build command
    cmd = [
        "semgrep",
        "scan",
        "--json",
        "--no-git-ignore",
        "--quiet",
        f"--config={config}",
        str(target),
    ]

    if additional_configs:
        for extra in additional_configs:
            cmd.extend([f"--config={extra}"])

    logger.info("Running semgrep on %s with config=%s", file_path, config)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        logger.warning(
            "Semgrep not found in PATH. Falling back to AST pattern scanner."
        )
        return ast_pattern_scan(file_path)
    except subprocess.TimeoutExpired:
        logger.error("Semgrep timed out after %ds on %s", timeout, file_path)
        return []
    except Exception as e:
        logger.error("Semgrep execution failed: %s", e)
        return []

    # Parse JSON output
    if not result.stdout.strip():
        logger.debug(
            "Semgrep returned no output for %s (exit=%d)", file_path, result.returncode
        )
        return ast_pattern_scan(file_path)

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        logger.error("Failed to parse semgrep JSON output: %s", e)
        return []

    matches: List[SemgrepMatch] = []
    raw_results = data.get("results", [])

    for item in raw_results:
        try:
            match = _parse_semgrep_result(item)
            if match:
                matches.append(match)
        except Exception as e:
            logger.warning("Failed to parse semgrep result item: %s", e)
            continue

    logger.info("Semgrep found %d matches in %s", len(matches), file_path)

    # If semgrep found nothing, supplement with AST scan
    if not matches:
        ast_matches = ast_pattern_scan(file_path)
        if ast_matches:
            logger.info(
                "AST scanner found %d additional patterns in %s",
                len(ast_matches),
                file_path,
            )
            matches.extend(ast_matches)

    return matches


def _parse_semgrep_result(item: Dict[str, Any]) -> Optional[SemgrepMatch]:
    """Parse a single semgrep result dict into a SemgrepMatch."""
    check_id = item.get("check_id", "unknown-rule")
    path = item.get("path", "")
    start = item.get("start", {})
    end = item.get("end", {})
    extra = item.get("extra", {})

    message = extra.get("message", check_id)
    severity_raw = extra.get("severity", "WARNING")
    lines = extra.get("lines", "")

    # Format snippet as markdown code block
    snippet = (
        f"```python\n{lines.rstrip()}\n```" if lines else "```python\n# no snippet\n```"
    )

    return SemgrepMatch(
        rule_id=check_id,
        message=message,
        severity=_map_severity(severity_raw).value,
        path=path,
        start_line=start.get("line", 0),
        end_line=end.get("line", 0),
        snippet=snippet,
        extra={
            "metadata": extra.get("metadata", {}),
            "fix": extra.get("fix"),
            "fingerprint": extra.get("fingerprint"),
        },
    )


# ---------------------------------------------------------------------------
# AST Pattern Scanner (Pure Python fallback)
# ---------------------------------------------------------------------------


# Security-sensitive sink patterns for AST analysis
DANGEROUS_CALLS = {
    # Command injection
    "os.system": ("Command Injection", Severity.HIGH),
    "os.popen": ("Command Injection", Severity.HIGH),
    "subprocess.call": ("Command Injection", Severity.MEDIUM),
    "subprocess.run": ("Command Injection", Severity.MEDIUM),
    "subprocess.Popen": ("Command Injection", Severity.HIGH),
    "eval": ("Code Injection", Severity.CRITICAL),
    "exec": ("Code Injection", Severity.CRITICAL),
    "compile": ("Code Injection", Severity.HIGH),
    # SQL injection risks
    "execute": ("SQL Injection Risk", Severity.MEDIUM),
    "executemany": ("SQL Injection Risk", Severity.MEDIUM),
    "raw": ("SQL Injection Risk", Severity.MEDIUM),
    "RawSQL": ("SQL Injection Risk", Severity.HIGH),
    "extra": ("SQL Injection Risk", Severity.MEDIUM),
    # Deserialization
    "pickle.loads": ("Insecure Deserialization", Severity.CRITICAL),
    "pickle.load": ("Insecure Deserialization", Severity.CRITICAL),
    "yaml.load": ("Insecure Deserialization", Severity.HIGH),
    "marshal.loads": ("Insecure Deserialization", Severity.HIGH),
    # SSRF / Path traversal
    "urllib.urlopen": ("SSRF Risk", Severity.MEDIUM),
    "requests.get": ("SSRF Risk", Severity.LOW),
    "requests.post": ("SSRF Risk", Severity.LOW),
    "open": ("Path Traversal Risk", Severity.LOW),
    # Crypto weaknesses
    "hashlib.md5": ("Weak Cryptography", Severity.MEDIUM),
    "hashlib.sha1": ("Weak Cryptography", Severity.LOW),
    "DES": ("Weak Cryptography", Severity.HIGH),
    # Template injection
    "render_template_string": ("SSTI Risk", Severity.HIGH),
    "Template": ("SSTI Risk", Severity.MEDIUM),
    "Markup": ("XSS Risk", Severity.MEDIUM),
}


class ASTPatternVisitor(ast.NodeVisitor):
    """Visit AST nodes to find dangerous call patterns."""

    def __init__(self, source_lines: List[str], file_path: str):
        self.source_lines = source_lines
        self.file_path = file_path
        self.findings: List[SemgrepMatch] = []

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Resolve a Call node to a dotted name string."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        return None

    def _get_snippet(self, node: ast.AST) -> str:
        """Extract source snippet for an AST node."""
        try:
            start = node.lineno - 1  # type: ignore[attr-defined]
            end = getattr(node, "end_lineno", start + 1)
            lines = self.source_lines[start:end]
            code = "\n".join(lines)
            return f"```python\n{code.rstrip()}\n```"
        except (AttributeError, IndexError):
            return "```python\n# snippet unavailable\n```"

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        """Check each Call node against our dangerous patterns."""
        call_name = self._get_call_name(node)
        if call_name:
            for pattern, (vuln_type, severity) in DANGEROUS_CALLS.items():
                if call_name == pattern or call_name.endswith(f".{pattern}"):
                    self.findings.append(
                        SemgrepMatch(
                            rule_id=f"ast-scan.{vuln_type.lower().replace(' ', '-')}",
                            message=(
                                f"Potentially dangerous call to `{call_name}` — "
                                f"possible {vuln_type}"
                            ),
                            severity=severity.value,
                            path=self.file_path,
                            start_line=node.lineno,  # type: ignore[attr-defined]
                            end_line=getattr(node, "end_lineno", node.lineno),  # type: ignore
                            snippet=self._get_snippet(node),
                            extra={"source": "ast-pattern-scanner"},
                        )
                    )
                    break  # Only report the highest-priority match per call

        self.generic_visit(node)


def ast_pattern_scan(file_path: str) -> List[SemgrepMatch]:
    """
    Pure-Python AST-based security pattern scanner.
    Used as a fallback when semgrep is unavailable.

    Args:
        file_path: Path to the Python file.

    Returns:
        List of SemgrepMatch objects for dangerous patterns found.
    """
    path = Path(file_path)
    if not path.exists():
        return []

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError) as e:
        logger.warning("AST scan failed for %s: %s", file_path, e)
        return []

    source_lines = source.splitlines()
    visitor = ASTPatternVisitor(source_lines=source_lines, file_path=file_path)
    visitor.visit(tree)

    return visitor.findings


# ---------------------------------------------------------------------------
# query_code Tool (Semantic Search Interface)
# ---------------------------------------------------------------------------


def query_code(
    engine: VectorEngine,
    query: str,
    n_results: int = 5,
    file_filter: Optional[str] = None,
) -> List[str]:
    """
    Semantic search over the indexed code base.
    Returns formatted code snippet strings for agent consumption.

    Args:
        engine: Initialized VectorEngine instance.
        query: Natural language description of what to find.
        n_results: Max results to return.
        file_filter: Restrict search to a specific file.

    Returns:
        List of formatted strings with source code and metadata.
    """
    results = engine.query(
        query_text=query,
        n_results=n_results,
        file_filter=file_filter,
    )

    snippets: List[str] = []
    for result in results:
        meta = result.get("metadata", {})
        doc = result.get("document", "")
        dist = result.get("distance", 1.0)
        similarity = round(1.0 - dist, 3)

        header = (
            f"# File: {meta.get('file_path', 'unknown')}\n"
            f"# {meta.get('node_type', 'code').title()}: {meta.get('qualified_name', '')}\n"
            f"# Lines: {meta.get('start_line', '?')}–{meta.get('end_line', '?')}\n"
            f"# Similarity: {similarity:.3f}\n"
            f"# Security hint: {meta.get('complexity_hint', 'none')}\n"
        )

        snippet = f"{header}```python\n{doc}\n```"
        snippets.append(snippet)

    return snippets
