from db_connector import DBConnector
from api.config import settings

async def health_check()->str:
    neo4j_status = "ok"

    connector = DBConnector(
        uri=settings.neo4j_uri,
        username=settings.neo4j_username,
        password=settings.neo4j_password,
    )

    with connector:
        connector.query("RETURN 1")

    return  neo4j_status
