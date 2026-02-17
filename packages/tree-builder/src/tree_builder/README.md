# TreeBuilder

Recursively scans a directory and produces a tree ontology. Every file and directory is represented as a node with its name, relative path, and relationships (parent, children, depth).

## Node schema

```json
{
  "fn": "name of the file or directory",
  "fp": "relative path from the scanned root",
  "parent": "relative path of the parent directory (null for root)",
  "children": ["relative paths of direct children"],
  "depth": "The relative depth of the item",
  "artifacts": ["A list of filenames that will be used to make relationships between the file or dir and other objects"],
  "temperature": "The temperature of the model",
  "confidence": "The confidence of the model",
  "examination": "The model response from the model after examining the object",
  "model": "The name of the model used"
}
```

`children` is populated only for directories; files always receive an empty list.

## File structure

```
treebuilder/
├── build_tree.py          # entry point (CLI + importable library)
└── components/
    ├── __init__.py        # re-exports Node, Relationships, scan_directory
    ├── node.py            # Node and Relationships dataclasses
    └── scanner.py         # recursive directory walker
```

## Usage

### CLI

```bash
# print JSON tree to stdout
python build_tree.py /path/to/directory

# write JSON tree to a file
python build_tree.py /path/to/directory -o output.json
```

### Library

```python
from build_tree import build_tree

nodes = build_tree("/path/to/directory")
for node in nodes:
    print(node["fp"], "depth:", node["relationships"]["depth"])
```

