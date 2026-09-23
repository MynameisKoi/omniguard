from neo4j import GraphDatabase
from config import NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD 

auth = (NEO4J_USER, NEO4J_PASSWORD)
driver = GraphDatabase.driver(NEO4J_URI, auth=auth)