import os

from dotenv import load_dotenv

# reads backend/.env into the environment.
# this is the only place in the app that does it.
load_dotenv()


# Mongo - raw alert storage
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "omniguard")

# Neo4j - entity graph
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")

# no default - a password should never fall back to anything, least of all
# neo4j's factory default. fail loudly at startup instead.
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
if not NEO4J_PASSWORD:
    raise RuntimeError(
        "NEO4J_PASSWORD is not set. Copy backend/.env.example to backend/.env "
        "and set it to your Neo4j password."
    )

# who can call this API from a browser
CORS_ORIGINS = ["http://localhost:5173"]