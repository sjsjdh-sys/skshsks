from collections.abc import Generator
from typing import Annotated

from fastapi import Depends

from db_connector import DBConnector

from tool_api.config import settings


def get_db() -> Generator[DBConnector, None, None]:
    """FastAPI dependency that opens and closes a DBConnector per request."""
    connector = DBConnector(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
    )
    with connector:
        yield connector


DB = Annotated[DBConnector, Depends(get_db)]
