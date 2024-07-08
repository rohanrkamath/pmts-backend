from pymongo import MongoClient, ASCENDING
from pymongo.errors import PyMongoError

MONGO_URI = 'mongodb://root:example@projects_db:27017'

client = MongoClient(MONGO_URI)

db = client['projects']