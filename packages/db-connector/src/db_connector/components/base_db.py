from abc import ABC, abstractmethod
from typing import Any


class BaseDB(ABC):
    """Abstract base class for all database connectors.

    Subclasses must implement connection lifecycle methods and
    node submission logic for their target database.
    """

    def __init__(self, uri: str, username: str, password: str) -> None:
        self._uri = uri
        self._username = username
        self._password = password
        self._connected: bool = False

    @property
    def is_connected(self) -> bool:
        """Return True if an active connection exists."""
        return self._connected

    @abstractmethod
    def connect(self) -> None:
        """Open a connection to the database."""
        ...

    @abstractmethod
    def disconnect(self) -> None:
        """Close the active connection to the database."""
        ...

    @abstractmethod
    def submit_node(self, label: str, properties: dict[str, Any]) -> dict[str, Any]:
        """Create a single node in the database.

        Args:
            label:      The node label / type.
            properties: Key-value pairs to store on the node.

        Returns:
            A dict representation of the created node.
        """
        ...

    @abstractmethod
    def submit_nodes(
        self, nodes: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Create multiple nodes in a single operation.

        Args:
            nodes: A list of dicts, each with keys ``label`` and
                   ``properties``.

        Returns:
            A list of dict representations of the created nodes.
        """
        ...

    @abstractmethod
    def query(self, query_str: str, parameters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """Execute a raw query against the database.

        Args:
            query_str:  The query string (e.g. Cypher for Neo4j).
            parameters: Optional parameters to bind into the query.

        Returns:
            A list of result records as dicts.
        """
        ...

    def __enter__(self) -> "BaseDB":
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.disconnect()
