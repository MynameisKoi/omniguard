from pymongo import MongoClient 

from config import MONGO_URI, MONGO_DB

client = MongoClient(MONGO_URI)

# creating the database and also the collection 
database = client[MONGO_DB]

brands_collection = database["brands"]

# the default signature set — seeded into Mongo on startup if empty, then
# served to the extension. We are just adding the brands here later we can make small endpoints to add brands or add directly in mongodb(second one doesn't seem like a good idea tho)
DEFAULT_BRANDS = [
    {"name": "GitHub",    "keywords": ["github"],                             "domains": ["github.com"]},
    {"name": "Instagram", "keywords": ["instagram"],                          "domains": ["instagram.com"]},
    {"name": "Facebook",  "keywords": ["facebook", "meta"],                   "domains": ["facebook.com"]},
    {"name": "Netflix",   "keywords": ["netflix"],                            "domains": ["netflix.com"]},
    {"name": "Google",    "keywords": ["google", "gmail"],                    "domains": ["google.com"]},
    {"name": "Microsoft", "keywords": ["microsoft", "office 365", "outlook"], "domains": ["microsoft.com", "live.com"]},
    {"name": "Claude",    "keywords": ["claude", "anthropic"],                "domains": ["claude.ai", "anthropic.com"]},
    {"name": "Apple",     "keywords": ["apple id", "icloud"],                 "domains": ["apple.com", "icloud.com"]},
    {"name": "TikTok",    "keywords": ["tiktok"],                             "domains": ["tiktok.com"]},
    {"name": "Amazon",    "keywords": ["amazon"],                             "domains": ["amazon.com"]},
]

def seed_brands():
    if brands_collection.count_documents({}) == 0:
        brands_collection.insert_many([dict(b) for b in DEFAULT_BRANDS])

seed_brands()