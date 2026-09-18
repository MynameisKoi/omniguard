import os 
from pymongo import MongoClient 

# Hardcoding the constant because we don't have a .env for now and we will move it to a docker
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
client = MongoClient(MONGO_URI)

# creating the database and also the collection 
database = client.omniguard
