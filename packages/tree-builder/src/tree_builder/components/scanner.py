import os
from typing import Optional

from .node import Node , NodeType , NodeStatus


def scan_directory(root: str) -> list[dict]:
    """
    Recursively scan a directory and return a list of Node dicts
    representing the tree ontology.

    Args:
        root: Absolute or relative path to the root directory to scan.

    Returns:
        A list of node dicts, one per file/directory discovered.
    """
    root = os.path.abspath(root)
    nodes: list[dict] = []

    def _walk(current_path: str, parent_rel: Optional[str], depth: int) -> None:
        rel_path = os.path.relpath(current_path, root)
        name = os.path.basename(current_path)

        is_dir = os.path.isdir(current_path)

        children_rel: list[str] = []
        if is_dir:
            try:
                entries = sorted(os.listdir(current_path))
            except PermissionError:
                entries = []
            for entry in entries:
                child_rel = os.path.join(rel_path, entry) if rel_path != "." else entry
                children_rel.append(child_rel)

        node = Node(
            fn=name,
            fp=rel_path,
            parent= parent_rel,
            depth=depth,
            children=children_rel,
            node_type=  NodeType.DIRECTORY if is_dir else  NodeType.FILE,
            status=NodeStatus.BUILT,
        )

        nodes.append(node.model_dump())

        if is_dir:
            try:
                entries = sorted(os.listdir(current_path))
            except PermissionError:
                return
            for entry in entries:
                child_path = os.path.join(current_path, entry)
                _walk(child_path, rel_path, depth + 1)

    _walk(root, None, 0)
    return nodes
