from pymongo import MongoClient, ASCENDING
from pymongo.errors import PyMongoError

MONGO_URI = 'mongodb://root:example@localhost:27018/'

client = MongoClient(MONGO_URI)

db = client['users']

db.users.create_index([("email", ASCENDING)], unique=True)
db.temp_users.create_index("created_at", expireAfterSeconds=300)