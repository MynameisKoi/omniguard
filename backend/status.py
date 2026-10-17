# Live health checks for the dashboard's system-status panel. Each check pokes
# one dependency and answers a simple yes/no. We never want a single dead service
# to blow up the whole status call, so every check keeps its own errors to itself
# and just reports False.

import httpx

from db import client as mongo_client
from graph import driver as neo4j_driver
from config import OLLAMA_URL


def check_mongo() -> bool:
    # cheapest "are you there?" Mongo has — a ping to the admin db
    try:
        mongo_client.admin.command("ping")
        return True
    except Exception:
        return False


def check_neo4j() -> bool:
    # open a session and run the most trivial query there is
    try:
        with neo4j_driver.session() as session:
            session.run("RETURN 1").consume()
        return True
    except Exception:
        return False


def check_ollama() -> bool:
    # if the model server answers its tags endpoint, the AI side is live
    try:
        r = httpx.get(f"{OLLAMA_URL}/api/tags", timeout=3.0)
        return r.status_code == 200
    except Exception:
        return False
