from pymongo import MongoClient 

from config import MONGO_URI, MONGO_DB

client = MongoClient(MONGO_URI)

# creating the database and also the collection 
database = client[MONGO_DB]
