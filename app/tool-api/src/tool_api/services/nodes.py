from db_connector import DBConnector
from typing import Any

async def create_node(label:str , properties:dict , db: DBConnector):
    return db.submit_node(label, properties)

async def create_nodes(nodes:list , db: DBConnector):
    payload = [
        {"label": n.label, "properties": n.properties} for n in nodes
    ]
    return db.submit_nodes(payload)


async def run_query(cypher:str , parameters:dict[str, Any] , db: DBConnector):
    return db.query(cypher,parameters)

async def get_nodes_by_label(label:str , db: DBConnector):
    return db.query(f"MATCH (n:{label}) RETURN n")