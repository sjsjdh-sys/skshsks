"""Unit tests for the API.

These tests use FastAPI's TestClient and mock the DBConnector so no real
Neo4j instance is required.
"""
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _mock_node(label: str = "TestNode", props: dict | None = None) -> dict:
    return {
        "element_id": "4:abc123:1",
        "labels": [label],
        "properties": props or {"name": "test"},
    }


# ── Root ──────────────────────────────────────────────────────────────────────

def test_root() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["message"] == "API"


# ── Health ────────────────────────────────────────────────────────────────────

def test_health_ok() -> None:
    mock_connector = MagicMock()
    mock_connector.__enter__ = MagicMock(return_value=mock_connector)
    mock_connector.__exit__ = MagicMock(return_value=False)
    mock_connector.query.return_value = [{"1": 1}]

    with patch("api.routers.health.DBConnector", return_value=mock_connector):
        response = client.get("/health")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["neo4j"] == "ok"


def test_health_neo4j_unavailable() -> None:
    with patch(
        "api.routers.health.DBConnector", side_effect=Exception("connection refused")
    ):
        response = client.get("/health")

    assert response.status_code == 503


# ── Nodes ─────────────────────────────────────────────────────────────────────

@pytest.fixture()
def mock_db():
    """Provide a mocked DBConnector via dependency override."""
    mock = MagicMock()
    mock.submit_node.return_value = _mock_node("Person", {"name": "Alice"})
    mock.submit_nodes.return_value = [
        _mock_node("Person", {"name": "Alice"}),
        _mock_node("Person", {"name": "Bob"}),
    ]
    mock.query.return_value = [{"n": _mock_node("Person", {"name": "Alice"})}]

    from api.dependencies import get_db
    app.dependency_overrides[get_db] = lambda: mock
    yield mock
    app.dependency_overrides.clear()


def test_create_node(mock_db: MagicMock) -> None:
    response = client.post(
        "/api/v1/nodes",
        json={"label": "Person", "properties": {"name": "Alice"}},
    )
    assert response.status_code == 201
    data = response.json()
    assert data["labels"] == ["Person"]
    assert data["properties"]["name"] == "Alice"


def test_create_nodes_batch(mock_db: MagicMock) -> None:
    response = client.post(
        "/api/v1/nodes/batch",
        json={
            "nodes": [
                {"label": "Person", "properties": {"name": "Alice"}},
                {"label": "Person", "properties": {"name": "Bob"}},
            ]
        },
    )
    assert response.status_code == 201
    assert len(response.json()) == 2


def test_get_nodes_by_label(mock_db: MagicMock) -> None:
    response = client.get("/api/v1/nodes/Person")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_run_query(mock_db: MagicMock) -> None:
    response = client.post(
        "/api/v1/nodes/query",
        json={"cypher": "MATCH (n) RETURN n LIMIT 10"},
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)
