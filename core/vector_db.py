"""
core/vector_db.py - AST-Aware Code Indexer + ChromaDB Vector Engine

Parses Python source files using the `ast` module to extract individual
FunctionDef and ClassDef nodes. Each node is stored as a separate document
in ChromaDB with rich metadata for precise retrieval.

Embedding backends (set EMBEDDING_BACKEND env var):
  onnx               → ChromaDB's built-in ONNX all-MiniLM-L6-v2 (DEFAULT, no torch)
  openai             → OpenAI text-embedding-3-small (needs OPENAI_API_KEY)
  cohere             → Cohere embed-english-v3.0 (needs COHERE_API_KEY)
  sentence_transformers → Local torch model (needs torch installed separately)
"""

from __future__ import annotations

import ast
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from chromadb.config import Settings

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", ".chroma_db")
COLLECTION_NAME = "code_chunks"

# Embedding backend: "onnx" | "openai" | "cohere" | "sentence_transformers"
EMBEDDING_BACKEND = os.getenv("EMBEDDING_BACKEND", "onnx")


# ---------------------------------------------------------------------------
# AST Data Structures
# ---------------------------------------------------------------------------


@dataclass
class CodeChunk:
    """Represents a single extractable code unit from a Python file."""

    chunk_id: str
    file_path: str
    node_type: str  # "function" | "class" | "method"
    name: str
    qualified_name: str  # ClassName.method_name for methods
    signature: str
    source: str  # Raw source lines
    start_line: int
    end_line: int
    parent_class: Optional[str] = None
    decorators: List[str] = field(default_factory=list)
    docstring: Optional[str] = None
    complexity_hint: str = ""  # "entry_point" | "database" | "auth" | ""


# ---------------------------------------------------------------------------
# AST Extraction Logic
# ---------------------------------------------------------------------------


class ASTCodeExtractor:
    """
    Walks a Python AST tree and extracts FunctionDef/ClassDef nodes
    as discrete CodeChunks with full metadata.
    """

    ENTRY_POINT_PATTERNS = {
        "route",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "api",
        "endpoint",
        "view",
        "handler",
        "webhook",
        "request",
        "response",
        "handle",
    }
    DATABASE_PATTERNS = {
        "query",
        "execute",
        "cursor",
        "select",
        "insert",
        "update",
        "delete",
        "fetch",
        "commit",
        "session",
        "filter",
        "orm",
        "model",
    }
    AUTH_PATTERNS = {
        "auth",
        "login",
        "logout",
        "token",
        "password",
        "credential",
        "permission",
        "role",
        "jwt",
        "oauth",
        "authenticate",
        "authorize",
    }

    def __init__(self, source: str, file_path: str):
        self.source = source
        self.source_lines = source.splitlines()
        self.file_path = file_path
        self.chunks: List[CodeChunk] = []

    def _get_lines(self, node: ast.AST) -> str:
        try:
            start = node.lineno - 1  # type: ignore[attr-defined]
            end = node.end_lineno  # type: ignore[attr-defined]
            return "\n".join(self.source_lines[start:end])
        except (AttributeError, IndexError):
            return ""

    def _build_signature(self, node: Any) -> str:
        args = []
        func_args = node.args
        for a in getattr(func_args, "posonlyargs", []):
            args.append(a.arg)
        for a in func_args.args:
            args.append(a.arg)
        if func_args.vararg:
            args.append(f"*{func_args.vararg.arg}")
        for a in func_args.kwonlyargs:
            args.append(a.arg)
        if func_args.kwarg:
            args.append(f"**{func_args.kwarg.arg}")
        kind = "async def" if isinstance(node, ast.AsyncFunctionDef) else "def"
        return f"{kind} {node.name}({', '.join(args)})"

    def _get_decorators(self, node: Any) -> List[str]:
        decs = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decs.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                val = dec.value
                prefix = val.id if isinstance(val, ast.Name) else "?"
                decs.append(f"{prefix}.{dec.attr}")
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    decs.append(dec.func.id)
                elif isinstance(dec.func, ast.Attribute):
                    decs.append(dec.func.attr)
        return decs

    def _classify_chunk(self, name: str, decorators: List[str]) -> str:
        name_lower = name.lower()
        dec_lower = " ".join(decorators).lower()
        combined = f"{name_lower} {dec_lower}"
        if any(p in combined for p in self.ENTRY_POINT_PATTERNS):
            return "entry_point"
        if any(p in combined for p in self.DATABASE_PATTERNS):
            return "database"
        if any(p in combined for p in self.AUTH_PATTERNS):
            return "auth"
        return ""

    def _make_chunk_id(self, file_path: str, name: str, line: int) -> str:
        safe_path = file_path.replace("/", "_").replace("\\", "_").replace(".", "_")
        return f"{safe_path}::{name}::{line}"

    def _extract_docstring(self, node: ast.AST) -> Optional[str]:
        try:
            return ast.get_docstring(node)  # type: ignore[arg-type]
        except Exception:
            return None

    def extract(self) -> List[CodeChunk]:
        try:
            tree = ast.parse(self.source)
        except SyntaxError as e:
            logger.warning("SyntaxError parsing %s: %s", self.file_path, e)
            return []
        self._walk_tree(tree, parent_class=None)
        return self.chunks

    def _walk_tree(self, tree: ast.AST, parent_class: Optional[str]) -> None:
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.ClassDef):
                self._handle_class(node)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._handle_function(node, parent_class=parent_class)

    def _handle_class(self, node: ast.ClassDef) -> None:
        source_text = self._get_lines(node)
        chunk_id = self._make_chunk_id(self.file_path, node.name, node.lineno)
        self.chunks.append(
            CodeChunk(
                chunk_id=chunk_id,
                file_path=self.file_path,
                node_type="class",
                name=node.name,
                qualified_name=node.name,
                signature=f"class {node.name}",
                source=source_text,
                start_line=node.lineno,
                end_line=node.end_lineno,  # type: ignore[attr-defined]
                docstring=self._extract_docstring(node),
            )
        )
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._handle_function(child, parent_class=node.name)

    def _handle_function(self, node: Any, parent_class: Optional[str]) -> None:
        source_text = self._get_lines(node)
        decorators = self._get_decorators(node)
        signature = self._build_signature(node)
        qualified = f"{parent_class}.{node.name}" if parent_class else node.name
        chunk_id = self._make_chunk_id(self.file_path, qualified, node.lineno)
        complexity_hint = self._classify_chunk(node.name, decorators)
        self.chunks.append(
            CodeChunk(
                chunk_id=chunk_id,
                file_path=self.file_path,
                node_type="method" if parent_class else "function",
                name=node.name,
                qualified_name=qualified,
                signature=signature,
                source=source_text,
                start_line=node.lineno,
                end_line=node.end_lineno,  # type: ignore[attr-defined]
                parent_class=parent_class,
                decorators=decorators,
                docstring=self._extract_docstring(node),
                complexity_hint=complexity_hint,
            )
        )
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._handle_function(child, parent_class=parent_class or node.name)


# ---------------------------------------------------------------------------
# Embedding Function Factory
# ---------------------------------------------------------------------------


def _build_embedding_fn(backend: str) -> Optional[Any]:
    """
    Build a ChromaDB-compatible embedding function.

    Defaults to the built-in ONNX runtime — no torch required.
    Falls back gracefully through each tier.
    """
    b = backend.lower()

    if b == "openai":
        try:
            from chromadb.utils.embedding_functions import OpenAIEmbeddingFunction

            fn = OpenAIEmbeddingFunction(
                api_key=os.environ["OPENAI_API_KEY"],
                model_name=os.getenv(
                    "OPENAI_EMBEDDING_MODEL", "text-embedding-3-small"
                ),
            )
            logger.info("Embedding backend: OpenAI text-embedding-3-small")
            return fn
        except KeyError:
            logger.error("OPENAI_API_KEY not set. Falling back to ONNX.")
        except Exception as e:
            logger.error("OpenAI embedding init failed: %s. Falling back to ONNX.", e)

    elif b == "cohere":
        try:
            from chromadb.utils.embedding_functions import CohereEmbeddingFunction

            fn = CohereEmbeddingFunction(
                api_key=os.environ["COHERE_API_KEY"],
                model_name=os.getenv("COHERE_EMBEDDING_MODEL", "embed-english-v3.0"),
            )
            logger.info("Embedding backend: Cohere embed-english-v3.0")
            return fn
        except KeyError:
            logger.error("COHERE_API_KEY not set. Falling back to ONNX.")
        except Exception as e:
            logger.error("Cohere embedding init failed: %s. Falling back to ONNX.", e)

    elif b == "sentence_transformers":
        try:
            from chromadb.utils.embedding_functions import (
                SentenceTransformerEmbeddingFunction,
            )

            model_name = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
            fn = SentenceTransformerEmbeddingFunction(model_name=model_name)
            logger.info("Embedding backend: SentenceTransformers (%s)", model_name)
            return fn
        except ImportError as e:
            logger.error(
                "SentenceTransformers unavailable (torch not installed?): %s. "
                "Falling back to ONNX.",
                e,
            )

    # ── Default / fallback: ChromaDB built-in ONNX ──────────────────────────
    # chromadb ships onnxruntime as a direct dependency and bundles a MiniLM
    # model. This works on Python 3.8–3.13 without installing torch at all.
    try:
        from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2

        fn = ONNXMiniLM_L6_V2()
        logger.info(
            "Embedding backend: ChromaDB built-in ONNX (all-MiniLM-L6-v2) — no torch needed"
        )
        return fn
    except ImportError:
        # Older chromadb versions may not expose this class name
        logger.warning(
            "ONNXMiniLM_L6_V2 not found in this chromadb version. "
            "Using chromadb's internal default embedder."
        )
        return None  # chromadb falls back to its own internal default


# ---------------------------------------------------------------------------
# ChromaDB Vector Engine
# ---------------------------------------------------------------------------


class VectorEngine:
    """
    Manages ChromaDB connections and provides semantic search
    over AST-extracted code chunks.
    """

    def __init__(self, persist_dir: str = CHROMA_PERSIST_DIR):
        self.persist_dir = persist_dir
        self._client: Optional[chromadb.ClientAPI] = None
        self._collection: Optional[chromadb.Collection] = None
        self._embedding_fn_cache: Optional[Any] = None

    def _get_embedding_fn(self) -> Optional[Any]:
        """Lazily initialize the embedding function."""
        if self._embedding_fn_cache is None:
            self._embedding_fn_cache = _build_embedding_fn(EMBEDDING_BACKEND)
        return self._embedding_fn_cache

    def initialize(self) -> None:
        """Set up ChromaDB client and collection."""
        try:
            self._client = chromadb.PersistentClient(
                path=self.persist_dir,
                settings=Settings(anonymized_telemetry=False),
            )

            embed_fn = self._get_embedding_fn()
            collection_kwargs: Dict[str, Any] = {
                "name": COLLECTION_NAME,
                "metadata": {"hnsw:space": "cosine"},
            }
            if embed_fn is not None:
                collection_kwargs["embedding_function"] = embed_fn

            self._collection = self._client.get_or_create_collection(
                **collection_kwargs
            )

            logger.info(
                "ChromaDB initialized at '%s'. Collection '%s' has %d documents.",
                self.persist_dir,
                COLLECTION_NAME,
                self._collection.count(),
            )
        except Exception as e:
            logger.error("Failed to initialize ChromaDB: %s", e)
            raise

    def _collection_ready(self) -> chromadb.Collection:
        if self._collection is None:
            raise RuntimeError("VectorEngine not initialized. Call initialize() first.")
        return self._collection

    def index_file(self, file_path: str) -> int:
        """
        Parse a Python file with AST, extract code chunks, upsert into Chroma.
        Returns the number of chunks indexed.
        """
        collection = self._collection_ready()

        try:
            source = Path(file_path).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.error("Cannot read file %s: %s", file_path, e)
            return 0

        extractor = ASTCodeExtractor(source=source, file_path=file_path)
        chunks = extractor.extract()

        if not chunks:
            logger.debug("No extractable chunks in %s", file_path)
            return 0

        documents: List[str] = []
        metadatas: List[Dict[str, Any]] = []
        ids: List[str] = []

        for chunk in chunks:
            doc_parts = [chunk.signature]
            if chunk.docstring:
                doc_parts.append(chunk.docstring)
            doc_parts.append(chunk.source)
            doc_text = "\n".join(doc_parts)

            documents.append(doc_text)
            ids.append(chunk.chunk_id)
            metadatas.append(
                {
                    "file_path": chunk.file_path,
                    "node_type": chunk.node_type,
                    "name": chunk.name,
                    "qualified_name": chunk.qualified_name,
                    "signature": chunk.signature,
                    "start_line": chunk.start_line,
                    "end_line": chunk.end_line,
                    "parent_class": chunk.parent_class or "",
                    "decorators": ", ".join(chunk.decorators),
                    "complexity_hint": chunk.complexity_hint,
                    "has_docstring": bool(chunk.docstring),
                }
            )

        try:
            collection.upsert(documents=documents, metadatas=metadatas, ids=ids)
            logger.info("Indexed %d chunks from %s", len(chunks), file_path)
        except Exception as e:
            logger.error("Failed to upsert chunks from %s: %s", file_path, e)
            return 0

        return len(chunks)

    def query(
        self,
        query_text: str,
        n_results: int = 5,
        file_filter: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Semantic search over indexed code chunks."""
        collection = self._collection_ready()
        total = collection.count()
        if total == 0:
            return []

        where_clause: Optional[Dict[str, Any]] = None
        if file_filter:
            where_clause = {"file_path": {"$eq": file_filter}}

        try:
            results = collection.query(
                query_texts=[query_text],
                n_results=min(n_results, max(1, total)),
                where=where_clause,
                include=["documents", "metadatas", "distances"],
            )
        except Exception as e:
            logger.error("ChromaDB query failed: %s", e)
            return []

        output = []
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        dists = results.get("distances", [[]])[0]

        for doc, meta, dist in zip(docs, metas, dists):
            output.append({"document": doc, "metadata": meta, "distance": dist})

        return output

    def get_by_name(
        self,
        function_name: str,
        file_path: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a specific function/class by name (exact match)."""
        collection = self._collection_ready()
        where: Dict[str, Any] = {"name": {"$eq": function_name}}
        if file_path:
            where = {"$and": [where, {"file_path": {"$eq": file_path}}]}

        try:
            results = collection.get(where=where, include=["documents", "metadatas"])
        except Exception as e:
            logger.error("get_by_name failed for '%s': %s", function_name, e)
            return None

        docs = results.get("documents", [])
        metas = results.get("metadatas", [])
        if not docs:
            return None
        return {"document": docs[0], "metadata": metas[0]}

    def count(self) -> int:
        return self._collection_ready().count()

    def clear_file(self, file_path: str) -> None:
        """Remove all chunks associated with a file (for re-indexing)."""
        collection = self._collection_ready()
        try:
            results = collection.get(
                where={"file_path": {"$eq": file_path}}, include=[]
            )
            ids = results.get("ids", [])
            if ids:
                collection.delete(ids=ids)
                logger.info("Cleared %d chunks for %s", len(ids), file_path)
        except Exception as e:
            logger.warning("Failed to clear file %s from Chroma: %s", file_path, e)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[VectorEngine] = None


def get_engine(persist_dir: str = CHROMA_PERSIST_DIR) -> VectorEngine:
    """Get or create the global VectorEngine singleton."""
    global _engine
    if _engine is None:
        _engine = VectorEngine(persist_dir=persist_dir)
        _engine.initialize()
    return _engine
