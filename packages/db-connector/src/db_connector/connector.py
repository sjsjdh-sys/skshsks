from typing import Any

from db_connector.components import BaseDB, Neo4jDB


class DBConnector:
    """High-level interface for submitting nodes to a database.

    Wraps any :class:`~db_connector.components.BaseDB` implementation and
    exposes a simplified API for node operations.  The default backend is
    :class:`~db_connector.components.Neo4jDB`.

    Example  using as a context manager::

        connector = DBConnector(
            uri="bolt://localhost:7687",
            username="neo4j",
            password="secret",
        )
        with connector:
            node = connector.submit_node("Person", {"name": "Alice"})
            print(node)

    Example  manual connection management::

        connector = DBConnector(uri=..., username=..., password=...)
        connector.connect()
        connector.submit_nodes([
            {"label": "Movie", "properties": {"title": "Inception"}},
            {"label": "Movie", "properties": {"title": "Interstellar"}},
        ])
        connector.disconnect()
    """

    def __init__(
        self,
        uri: str,
        username: str,
        password: str,
        backend: type[BaseDB] = Neo4jDB,
    ) -> None:
        """Initialise the connector.

        Args:
            uri:      Connection URI for the target database.
            username: Database username.
            password: Database password.
            backend:  A :class:`BaseDB` subclass to use as the driver.
                      Defaults to :class:`Neo4jDB`.
        """
        self._db: BaseDB = backend(uri=uri, username=username, password=password)

    # ------------------------------------------------------------------
    # Connection lifecycle (delegates to the backend)
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Open the database connection."""
        self._db.connect()

    def disconnect(self) -> None:
        """Close the database connection."""
        self._db.disconnect()

    @property
    def is_connected(self) -> bool:
        """Return True when the underlying connection is active."""
        return self._db.is_connected

    # ------------------------------------------------------------------
    # Node operations
    # ------------------------------------------------------------------

    def submit_node(self, label: str, properties: dict[str, Any]) -> dict[str, Any]:
        """Create a single node in the database.

        Args:
            label:      Node label / type.
            properties: Key-value pairs to store on the node.

        Returns:
            A dict representation of the created node.
        """
        return self._db.submit_node(label, properties)

    def submit_nodes(
        self, nodes: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Create multiple nodes in a single transaction.

        Each item in *nodes* must contain:

        * ``"label"``      the node label
        * ``"properties"`` a dict of property key/value pairs

        Args:
            nodes: List of node descriptors.

        Returns:
            A list of dicts representing the created nodes.
        """
        return self._db.submit_nodes(nodes)

    # ------------------------------------------------------------------
    # Raw query passthrough
    # ------------------------------------------------------------------

    def query(
        self,
        query_str: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Execute a raw query against the database backend.

        Args:
            query_str:  Query string (Cypher for Neo4j).
            parameters: Optional parameter bindings.

        Returns:
            A list of result records as dicts.
        """
        return self._db.query(query_str, parameters)

    # ------------------------------------------------------------------
    # Context manager support
    # ------------------------------------------------------------------

    def __enter__(self) -> "DBConnector":
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.disconnect()
