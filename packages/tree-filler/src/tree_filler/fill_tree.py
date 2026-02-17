"""
TreeBuilder - recursively scans a directory and produces a tree ontology.

Each file and directory is represented as a node:

    {
        fn: <name of the file or directory>,
        fp: <relative path from the scanned root>,
        relationships: {
            parent: <relative path of the parent directory, or None for root>,
            children: [<relative paths of direct children>],  # dirs only
            depth: <integer depth from root>,
        }
    }

Usage (CLI):
    python build_tree.py <directory> [--output <file.json>]

Usage (library):
    from build_tree import build_tree
    nodes = build_tree("/path/to/dir")
"""

import argparse
import json
import sys
from tree_filler.components.examiner import examine_tree


def fill_tree(root: str) -> list[dict]:
    """Scan *root* and return the tree ontology as a list of node dicts."""
    return examine_tree(root)


def main() -> None:
    pass


if __name__ == "__main__":
    main()
