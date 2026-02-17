"""Tests for db_connector package.

All tests use mocking so no live Neo4j instance is required.
"""
from typing import Any
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from db_connector.components.base_db import BaseDB
from db_connector.components.neo4j_db import Neo4jDB
from db_connector.main import DBConnector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _ConcreteDB(BaseDB):
    """Minimal concrete subclass used to test the abstract interface."""

    def connect(self) -> None:
        self._connected = True

    def disconnect(self) -> None:
        self._connected = False

    def submit_node(self, label: str, properties: dict[str, Any]) -> dict[str, Any]:
        return {"label": label, "properties": properties}

    def submit_nodes(self, nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.submit_node(n["label"], n["properties"]) for n in nodes]

    def query(self, query_str: str, parameters: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        return []


# ---------------------------------------------------------------------------
# BaseDB tests
# ---------------------------------------------------------------------------

class TestBaseDB:
    def test_cannot_instantiate_directly(self):
        with pytest.raises(TypeError):
            BaseDB(uri="bolt://localhost", username="u", password="p")  # type: ignore[abstract]

    def test_concrete_subclass_instantiates(self):
        db = _ConcreteDB(uri="bolt://localhost", username="u", password="p")
        assert db is not None

    def test_is_connected_false_by_default(self):
        db = _ConcreteDB(uri="bolt://localhost", username="u", password="p")
        assert db.is_connected is False

    def test_context_manager_connects_and_disconnects(self):
        db = _ConcreteDB(uri="bolt://localhost", username="u", password="p")
        with db as ctx:
            assert ctx.is_connected is True
        assert db.is_connected is False

    def test_submit_node_returns_dict(self):
        db = _ConcreteDB(uri="bolt://localhost", username="u", password="p")
        result = db.submit_node("Person", {"name": "Alice"})
        assert result == {"label": "Person", "properties": {"name": "Alice"}}

    def test_submit_nodes_returns_list(self):
        db = _ConcreteDB(uri="bolt://localhost", username="u", password="p")
        nodes = [
            {"label": "Person", "properties": {"name": "Bob"}},
            {"label": "Person", "properties": {"name": "Carol"}},
        ]
        results = db.submit_nodes(nodes)
        assert len(results) == 2


# ---------------------------------------------------------------------------
# Neo4jDB tests (mocked driver)
# ---------------------------------------------------------------------------

@pytest.fixture()
def mock_driver():
    """Return a mock neo4j Driver."""
    driver = MagicMock()
    driver.verify_connectivity.return_value = None
    return driver


@pytest.fixture()
def neo4j_db(mock_driver):
    db = Neo4jDB(uri="bolt://localhost:7687", username="neo4j", password="test")
    with patch("db_connector.components.neo4j_db.GraphDatabase.driver", return_value=mock_driver):
        db.connect()
    return db, mock_driver


class TestNeo4jDB:
    def test_connect_sets_connected(self, mock_driver):
        db = Neo4jDB(uri="bolt://localhost:7687", username="neo4j", password="test")
        with patch("db_connector.components.neo4j_db.GraphDatabase.driver", return_value=mock_driver):
            db.connect()
        assert db.is_connected is True
        mock_driver.verify_connectivity.assert_called_once()

    def test_connect_is_idempotent(self, mock_driver):
        db = Neo4jDB(uri="bolt://localhost:7687", username="neo4j", password="test")
        with patch("db_connector.components.neo4j_db.GraphDatabase.driver", return_value=mock_driver):
            db.connect()
            db.connect()  # second call should be a no-op
        mock_driver.verify_connectivity.assert_called_once()

    def test_disconnect_clears_connected(self, neo4j_db):
        db, mock_driver = neo4j_db
        db.disconnect()
        assert db.is_connected is False
        mock_driver.close.assert_called_once()

    def test_submit_node_raises_when_not_connected(self):
        db = Neo4jDB(uri="bolt://localhost:7687", username="neo4j", password="test")
        with pytest.raises(RuntimeError, match="Not connected"):
            db.submit_node("Person", {"name": "Alice"})

    def test_submit_node_runs_cypher(self, neo4j_db):
        db, mock_driver = neo4j_db

        # Build a fake node record
        fake_node = MagicMock()
        fake_node.element_id = "4:abc:1"
        fake_node.labels = {"Person"}
        fake_node._properties = {"name": "Alice"}

        fake_record = MagicMock()
        fake_record.keys.return_value = ["n"]
        fake_record.__getitem__ = lambda self, key: fake_node

        fake_result = MagicMock()
        fake_result.__iter__ = MagicMock(return_value=iter([fake_record]))

        fake_session = MagicMock()
        fake_session.run.return_value = fake_result
        fake_session.__enter__ = MagicMock(return_value=fake_session)
        fake_session.__exit__ = MagicMock(return_value=False)

        mock_driver.session.return_value = fake_session

        result = db.submit_node("Person", {"name": "Alice"})

        assert result["labels"] == ["Person"]
        assert result["properties"] == {"name": "Alice"}
        assert result["element_id"] == "4:abc:1"

    def test_submit_nodes_raises_on_bad_input(self, neo4j_db):
        db, mock_driver = neo4j_db

        fake_tx = MagicMock()
        fake_tx.__enter__ = MagicMock(return_value=fake_tx)
        fake_tx.__exit__ = MagicMock(return_value=False)
        fake_session = MagicMock()
        fake_session.__enter__ = MagicMock(return_value=fake_session)
        fake_session.__exit__ = MagicMock(return_value=False)
        fake_session.begin_transaction.return_value = fake_tx
        mock_driver.session.return_value = fake_session

        with pytest.raises(ValueError, match="'label' and 'properties'"):
            db.submit_nodes([{"bad_key": "x"}])

    def test_query_raises_when_not_connected(self):
        db = Neo4jDB(uri="bolt://localhost:7687", username="neo4j", password="test")
        with pytest.raises(RuntimeError, match="Not connected"):
            db.query("MATCH (n) RETURN n")


# ---------------------------------------------------------------------------
# DBConnector tests
# ---------------------------------------------------------------------------

class TestDBConnector:
    def test_uses_neo4j_backend_by_default(self):
        connector = DBConnector(uri="bolt://localhost", username="u", password="p")
        assert isinstance(connector._db, Neo4jDB)

    def test_accepts_custom_backend(self):
        connector = DBConnector(
            uri="bolt://localhost", username="u", password="p",
            backend=_ConcreteDB,
        )
        assert isinstance(connector._db, _ConcreteDB)

    def test_context_manager_delegates_to_backend(self):
        connector = DBConnector(
            uri="bolt://localhost", username="u", password="p",
            backend=_ConcreteDB,
        )
        with connector as ctx:
            assert ctx.is_connected is True
        assert connector.is_connected is False

    def test_submit_node_delegates(self):
        connector = DBConnector(
            uri="bolt://localhost", username="u", password="p",
            backend=_ConcreteDB,
        )
        result = connector.submit_node("Movie", {"title": "Inception"})
        assert result["label"] == "Movie"
        assert result["properties"]["title"] == "Inception"

    def test_submit_nodes_delegates(self):
        connector = DBConnector(
            uri="bolt://localhost", username="u", password="p",
            backend=_ConcreteDB,
        )
        nodes = [
            {"label": "Movie", "properties": {"title": "A"}},
            {"label": "Movie", "properties": {"title": "B"}},
        ]
        results = connector.submit_nodes(nodes)
        assert len(results) == 2

    def test_query_delegates(self):
        connector = DBConnector(
            uri="bolt://localhost", username="u", password="p",
            backend=_ConcreteDB,
        )
        results = connector.query("MATCH (n) RETURN n")
        assert results == []
