from pymongo import MongoClient, ASCENDING
from pymongo.errors import PyMongoError

MONGO_URI = 'mongodb://root:example@localhost:27021/'

client = MongoClient(MONGO_URI)

db = client['comment_master']