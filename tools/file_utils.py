"""
tools/file_utils.py - File System Utilities for test

Provides list_files and read_function tools for use by the agents.
These are stateless utility functions that operate purely on the filesystem.
"""

from __future__ import annotations

import ast
import logging
import os
import re
import textwrap
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# Directories/files to skip during recursive listing
SKIP_DIRS = {
    "__pycache__",
    ".git",
    ".tox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    "dist",
    "build",
    ".eggs",
    "htmlcov",
    ".chroma_db",
}

SKIP_FILES = {
    "setup.py",
    "conftest.py",  # Not skipped — we want to audit these too
}


# ---------------------------------------------------------------------------
# list_files Tool
# ---------------------------------------------------------------------------


def list_files(repo_path: str, extensions: Tuple[str, ...] = (".py",)) -> List[str]:
    """
    Recursively list all Python files in a repository directory.
    Skips common non-code directories.

    Args:
        repo_path: Root directory to scan.
        extensions: File extensions to include.

    Returns:
        Sorted list of absolute file paths.

    Raises:
        ValueError: If repo_path doesn't exist or isn't a directory.
    """
    root = Path(repo_path).resolve()

    if not root.exists():
        raise ValueError(f"Repository path does not exist: {repo_path}")
    if not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {repo_path}")

    found: List[str] = []

    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place (modifies traversal)
        dirnames[:] = [
            d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
        ]

        for fname in filenames:
            if any(fname.endswith(ext) for ext in extensions):
                full_path = str(Path(dirpath) / fname)
                found.append(full_path)

    found.sort()
    logger.info("list_files: found %d files in %s", len(found), repo_path)
    return found


# ---------------------------------------------------------------------------
# read_function Tool
# ---------------------------------------------------------------------------


def read_function(
    file_path: str,
    function_name: str,
) -> Optional[str]:
    """
    Precisely retrieve a function's source code from a Python file by name.
    Uses AST parsing for accuracy; falls back to regex for edge cases.

    Args:
        file_path: Absolute or relative path to the Python file.
        function_name: Name of the function or method to retrieve.
                       Use 'ClassName.method_name' for methods.

    Returns:
        Source code of the function as a string, or None if not found.
    """
    path = Path(file_path)
    if not path.exists():
        logger.warning("read_function: file not found: %s", file_path)
        return None

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.error("read_function: cannot read %s: %s", file_path, e)
        return None

    # Handle 'ClassName.method_name' notation
    target_class: Optional[str] = None
    target_func: str = function_name

    if "." in function_name:
        parts = function_name.split(".", 1)
        target_class = parts[0]
        target_func = parts[1]

    result = _extract_via_ast(source, target_func, target_class)
    if result:
        return result

    # Fallback: regex-based extraction (less precise)
    logger.debug("AST extraction failed for '%s', trying regex fallback", function_name)
    return _extract_via_regex(source, target_func)


def _extract_via_ast(
    source: str,
    function_name: str,
    class_name: Optional[str] = None,
) -> Optional[str]:
    """Use the ast module to extract precise function source."""
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        logger.warning("AST parse failed: %s", e)
        return None

    lines = source.splitlines(keepends=True)

    def get_source_segment(node: ast.AST) -> str:
        start = node.lineno - 1  # type: ignore[attr-defined]
        end = node.end_lineno  # type: ignore[attr-defined]
        return "".join(lines[start:end])

    if class_name:
        # Find the class first, then the method
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == class_name:
                for child in ast.iter_child_nodes(node):
                    if (
                        isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and child.name == function_name
                    ):
                        return get_source_segment(child)
        return None

    # Top-level function search
    for node in ast.walk(tree):
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == function_name
        ):
            return get_source_segment(node)

    return None


def _extract_via_regex(source: str, function_name: str) -> Optional[str]:
    """
    Regex fallback for function extraction.
    Handles basic cases where AST parsing fails (e.g., syntax errors in file).
    """
    pattern = rf"^(async\s+)?def\s+{re.escape(function_name)}\s*\("
    lines = source.splitlines()

    start_idx: Optional[int] = None
    for i, line in enumerate(lines):
        if re.match(pattern, line.strip()):
            start_idx = i
            break

    if start_idx is None:
        return None

    # Collect lines until we return to the same indentation level
    base_indent = len(lines[start_idx]) - len(lines[start_idx].lstrip())
    collected = [lines[start_idx]]

    for line in lines[start_idx + 1 :]:
        if line.strip() == "":
            collected.append(line)
            continue
        current_indent = len(line) - len(line.lstrip())
        if current_indent <= base_indent and line.strip():
            break
        collected.append(line)

    return "\n".join(collected)


# ---------------------------------------------------------------------------
# read_file Tool (whole-file reading)
# ---------------------------------------------------------------------------


def read_file(file_path: str, max_lines: int = 1000) -> Optional[str]:
    """
    Read a file's full content, truncating at max_lines for safety.

    Args:
        file_path: Path to the file.
        max_lines: Maximum number of lines to return.

    Returns:
        File content as string, or None on error.
    """
    path = Path(file_path)
    if not path.exists():
        logger.warning("read_file: file not found: %s", file_path)
        return None

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        lines = source.splitlines()
        if len(lines) > max_lines:
            truncated = lines[:max_lines]
            truncated.append(
                f"\n... [TRUNCATED: {len(lines) - max_lines} more lines not shown]"
            )
            return "\n".join(truncated)
        return source
    except OSError as e:
        logger.error("read_file: cannot read %s: %s", file_path, e)
        return None


def get_file_stats(file_path: str) -> dict:
    """Return basic stats about a Python file without reading all content."""
    path = Path(file_path)
    stats: dict = {
        "path": str(path),
        "exists": path.exists(),
        "size_bytes": 0,
        "line_count": 0,
        "has_syntax_error": False,
    }

    if not path.exists():
        return stats

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        stats["size_bytes"] = path.stat().st_size
        stats["line_count"] = source.count("\n") + 1
        try:
            ast.parse(source)
        except SyntaxError:
            stats["has_syntax_error"] = True
    except OSError:
        pass

    return stats
