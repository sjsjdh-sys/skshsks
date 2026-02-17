from typing import Any

from neo4j import GraphDatabase, Driver, Session

from .base_db import BaseDB


class Neo4jDB(BaseDB):
    """Neo4j implementation of :class:`BaseDB`.

    Uses the official ``neo4j`` Python driver to manage a connection
    and submit nodes / queries to a Neo4j database.

    Example::

        db = Neo4jDB(uri="bolt://localhost:7687", username="neo4j", password="secret")
        with db:
            node = db.submit_node("Person", {"name": "Alice", "age": 30})
    """

    def __init__(self, uri: str, username: str, password: str) -> None:
        super().__init__(uri, username, password)
        self._driver: Driver | None = None

    # ------------------------------------------------------------------
    # Connection lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Open the Neo4j driver and verify connectivity."""
        if self._connected:
            return
        self._driver = GraphDatabase.driver(
            self._uri, auth=(self._username, self._password)
        )
        self._driver.verify_connectivity()
        self._connected = True

    def disconnect(self) -> None:
        """Close the Neo4j driver and release resources."""
        if self._driver is not None:
            self._driver.close()
            self._driver = None
        self._connected = False

    # ------------------------------------------------------------------
    # Node submission
    # ------------------------------------------------------------------

    def submit_node(self, label: str, properties: dict[str, Any]) -> dict[str, Any]:
        """Create a single node with the given label and properties.

        Args:
            label:      Neo4j node label (e.g. ``"Person"``).
            properties: Properties to set on the node.

        Returns:
            A dict containing the node's element id and properties.

        Raises:
            RuntimeError: If called before :meth:`connect`.
        """
        self._assert_connected()
        cypher = f"CREATE (n:{label} $props) RETURN n"
        results = self._run(cypher, {"props": properties})
        return results[0] if results else {}

    def submit_nodes(
        self, nodes: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Create multiple nodes in a single transaction.

        Each entry in *nodes* must have the keys:

        * ``label``      – the Neo4j node label
        * ``properties`` – a dict of property key/value pairs

        Args:
            nodes: List of node descriptors.

        Returns:
            A list of dicts, one per created node.

        Raises:
            RuntimeError: If called before :meth:`connect`.
            ValueError:   If any node dict is missing required keys.
        """
        self._assert_connected()
        created: list[dict[str, Any]] = []

        with self._driver.session() as session:  # type: ignore[union-attr]
            with session.begin_transaction() as tx:
                for node in nodes:
                    if "label" not in node or "properties" not in node:
                        raise ValueError(
                            "Each node must have 'label' and 'properties' keys. "
                            f"Got: {list(node.keys())}"
                        )
                    cypher = f"CREATE (n:{node['label']} $props) RETURN n"
                    result = tx.run(cypher, props=node["properties"])
                    for record in result:
                        created.append(self._record_to_dict(record["n"]))
                tx.commit()

        return created

    # ------------------------------------------------------------------
    # Raw query
    # ------------------------------------------------------------------

    def query(
        self,
        query_str: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a raw Cypher query.

        Args:
            query_str:  Cypher query string.
            parameters: Optional parameter bindings.

        Returns:
            A list of result records converted to dicts.

        Raises:
            RuntimeError: If called before :meth:`connect`.
        """
        self._assert_connected()
        return self._run(query_str, parameters or {})

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _assert_connected(self) -> None:
        if not self._connected or self._driver is None:
            raise RuntimeError(
                "Not connected. Call connect() or use the context manager first."
            )

    def _run(self, cypher: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        """Execute *cypher* inside a fresh session and return all records."""
        results: list[dict[str, Any]] = []
        with self._driver.session() as session:  # type: ignore[union-attr]
            result = session.run(cypher, **params)
            for record in result:
                row: dict[str, Any] = {}
                for key in record.keys():
                    value = record[key]
                    # Unwrap Neo4j node objects into plain dicts
                    if hasattr(value, "_properties"):
                        row[key] = self._record_to_dict(value)
                    else:
                        row[key] = value
                results.append(row)
        return results

    @staticmethod
    def _record_to_dict(node: Any) -> dict[str, Any]:
        """Convert a Neo4j Node object to a plain Python dict."""
        return {
            "element_id": node.element_id,
            "labels": list(node.labels),
            "properties": dict(node._properties),
        }
