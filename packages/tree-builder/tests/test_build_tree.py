"""
pytest suite for TreeBuilder.

Fixtures
--------
case1_single_file   depth 1 — root + 1 file
case2_flat_dir      depth 1 — root + 3 files, no subdirs
case3_shallow       depth 2 — root + 1 file + 1 subdir with 2 files
case4_medium        depth 3 — root + nested src/utils + docs branches
case5_deep          depth 4 — root + single chain 4 levels deep
"""

import os

import pytest

from tree_builder.build_tree import build_tree

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def nodes_by_fp(nodes: list[dict]) -> dict[str, dict]:
    """Return a mapping of fp -> node for easy lookup."""
    return {n["fp"]: n for n in nodes}


# ---------------------------------------------------------------------------
# Case 1 — single file, max depth 1
#
# case1_single_file/
# └── hello.txt
# ---------------------------------------------------------------------------

class TestCase1SingleFile:
    ROOT = os.path.join(FIXTURES, "case1_single_file")

    def setup_method(self):
        self.nodes = build_tree(self.ROOT)
        self.by_fp = nodes_by_fp(self.nodes)

    def test_node_count(self):
        # root dir + 1 file
        assert len(self.nodes) == 2

    def test_root_node(self):
        root = self.by_fp["."]
        assert root["fn"] == "case1_single_file"
        assert root["relationships"]["parent"] is None
        assert root["relationships"]["depth"] == 0
        assert "hello.txt" in root["relationships"]["children"]

    def test_file_node(self):
        node = self.by_fp["hello.txt"]
        assert node["fn"] == "hello.txt"
        assert node["relationships"]["parent"] == "."
        assert node["relationships"]["depth"] == 1
        assert node["relationships"]["children"] == []

    def test_max_depth(self):
        max_depth = max(n["relationships"]["depth"] for n in self.nodes)
        assert max_depth == 1


# ---------------------------------------------------------------------------
# Case 2 — flat dir, depth 1, multiple files
#
# case2_flat_dir/
# ├── a.txt
# ├── b.txt
# └── c.txt
# ---------------------------------------------------------------------------

class TestCase2FlatDir:
    ROOT = os.path.join(FIXTURES, "case2_flat_dir")

    def setup_method(self):
        self.nodes = build_tree(self.ROOT)
        self.by_fp = nodes_by_fp(self.nodes)

    def test_node_count(self):
        # root + 3 files
        assert len(self.nodes) == 4

    def test_root_children(self):
        root = self.by_fp["."]
        assert set(root["relationships"]["children"]) == {"a.txt", "b.txt", "c.txt"}

    def test_all_files_are_depth_1(self):
        for fp in ("a.txt", "b.txt", "c.txt"):
            assert self.by_fp[fp]["relationships"]["depth"] == 1

    def test_files_have_no_children(self):
        for fp in ("a.txt", "b.txt", "c.txt"):
            assert self.by_fp[fp]["relationships"]["children"] == []

    def test_files_parent_is_root(self):
        for fp in ("a.txt", "b.txt", "c.txt"):
            assert self.by_fp[fp]["relationships"]["parent"] == "."

    def test_max_depth(self):
        max_depth = max(n["relationships"]["depth"] for n in self.nodes)
        assert max_depth == 1


# ---------------------------------------------------------------------------
# Case 3 — shallow tree, depth 2
#
# case3_shallow/
# ├── readme.txt
# └── subdir/
#     ├── file1.txt
#     └── file2.txt
# ---------------------------------------------------------------------------

class TestCase3Shallow:
    ROOT = os.path.join(FIXTURES, "case3_shallow")

    def setup_method(self):
        self.nodes = build_tree(self.ROOT)
        self.by_fp = nodes_by_fp(self.nodes)

    def test_node_count(self):
        # root + readme.txt + subdir + file1.txt + file2.txt
        assert len(self.nodes) == 5

    def test_root_children(self):
        root = self.by_fp["."]
        assert set(root["relationships"]["children"]) == {"readme.txt", "subdir"}

    def test_subdir_node(self):
        subdir = self.by_fp["subdir"]
        assert subdir["fn"] == "subdir"
        assert subdir["relationships"]["depth"] == 1
        assert subdir["relationships"]["parent"] == "."
        assert set(subdir["relationships"]["children"]) == {
            "subdir/file1.txt",
            "subdir/file2.txt",
        }

    def test_nested_files(self):
        for fp in ("subdir/file1.txt", "subdir/file2.txt"):
            node = self.by_fp[fp]
            assert node["relationships"]["depth"] == 2
            assert node["relationships"]["parent"] == "subdir"
            assert node["relationships"]["children"] == []

    def test_max_depth(self):
        max_depth = max(n["relationships"]["depth"] for n in self.nodes)
        assert max_depth == 2


# ---------------------------------------------------------------------------
# Case 4 — medium tree, depth 3
#
# case4_medium/
# ├── config.txt
# ├── docs/
# │   └── guide.txt
# └── src/
#     ├── main.py
#     └── utils/
#         ├── helper.py
#         └── parser.py
# ---------------------------------------------------------------------------

class TestCase4Medium:
    ROOT = os.path.join(FIXTURES, "case4_medium")

    def setup_method(self):
        self.nodes = build_tree(self.ROOT)
        self.by_fp = nodes_by_fp(self.nodes)

    def test_node_count(self):
        # root, config.txt, docs, guide.txt, src, main.py, utils, helper.py, parser.py
        assert len(self.nodes) == 9

    def test_root_children(self):
        root = self.by_fp["."]
        assert set(root["relationships"]["children"]) == {"config.txt", "docs", "src"}

    def test_src_children(self):
        src = self.by_fp["src"]
        assert set(src["relationships"]["children"]) == {"src/main.py", "src/utils"}

    def test_utils_children(self):
        utils = self.by_fp["src/utils"]
        assert set(utils["relationships"]["children"]) == {
            "src/utils/helper.py",
            "src/utils/parser.py",
        }

    def test_depth_3_nodes(self):
        for fp in ("src/utils/helper.py", "src/utils/parser.py"):
            assert self.by_fp[fp]["relationships"]["depth"] == 3
            assert self.by_fp[fp]["relationships"]["parent"] == "src/utils"

    def test_docs_guide(self):
        guide = self.by_fp["docs/guide.txt"]
        assert guide["relationships"]["depth"] == 2
        assert guide["relationships"]["parent"] == "docs"

    def test_max_depth(self):
        max_depth = max(n["relationships"]["depth"] for n in self.nodes)
        assert max_depth == 3


# ---------------------------------------------------------------------------
# Case 5 — deep chain, depth 4
#
# case5_deep/
# ├── root.txt
# └── level1/
#     └── level2/
#         └── level3/
#             └── deep_file.txt
# ---------------------------------------------------------------------------

class TestCase5Deep:
    ROOT = os.path.join(FIXTURES, "case5_deep")

    def setup_method(self):
        self.nodes = build_tree(self.ROOT)
        self.by_fp = nodes_by_fp(self.nodes)

    def test_node_count(self):
        # root, root.txt, level1, level2, level3, deep_file.txt
        assert len(self.nodes) == 6

    def test_chain_depths(self):
        expected = {
            ".": 0,
            "root.txt": 1,
            "level1": 1,
            "level1/level2": 2,
            "level1/level2/level3": 3,
            "level1/level2/level3/deep_file.txt": 4,
        }
        for fp, depth in expected.items():
            assert self.by_fp[fp]["relationships"]["depth"] == depth, fp

    def test_chain_parents(self):
        expected = {
            ".": None,
            "root.txt": ".",
            "level1": ".",
            "level1/level2": "level1",
            "level1/level2/level3": "level1/level2",
            "level1/level2/level3/deep_file.txt": "level1/level2/level3",
        }
        for fp, parent in expected.items():
            assert self.by_fp[fp]["relationships"]["parent"] == parent, fp

    def test_deep_file_has_no_children(self):
        node = self.by_fp["level1/level2/level3/deep_file.txt"]
        assert node["relationships"]["children"] == []

    def test_max_depth(self):
        max_depth = max(n["relationships"]["depth"] for n in self.nodes)
        assert max_depth == 4
