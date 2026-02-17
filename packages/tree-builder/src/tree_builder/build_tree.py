"""
TreeBuilder - recursively scans a directory and produces a tree ontology.

Each file and directory is represented as a node:

{
  "fn": <name of the file or directory>,
  "fp": <relative path from the scanned root>,
  "parent": <relative path of the parent directory (null for root)>,
  "children": [<relative paths of direct children>],
  "depth": <The relative depth of the item>,
  "artifacts": [<A list of filenames that will be used to make relationships between the file or dir and other objects>],
  "temperature": <The temperature of the model>,
  "confidence": <The confidence of the model>,
  "examination": <The model response from the model after examining the object>,
  "model": <The name of the model used>
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

from tree_builder.components.scanner import scan_directory


def build_tree(root: str) -> list[dict]:
    """Scan *root* and return the tree ontology as a list of node dicts."""
    return scan_directory(root)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Recursively scan a directory and output a tree ontology."
    )
    parser.add_argument("directory", help="Root directory to scan")
    parser.add_argument(
        "--output",
        "-o",
        metavar="FILE",
        help="Write JSON output to FILE instead of stdout",
    )
    args = parser.parse_args()

    nodes = build_tree(args.directory)
    output = json.dumps(nodes, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        print(f"Tree written to {args.output} ({len(nodes)} nodes)")
    else:
        print(output)


if __name__ == "__main__":
    main()
