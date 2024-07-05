from pymongo import DESCENDING
from pymongo.collection import Collection

# Check if a user exists in the given collection
def check_user_exists(collection: Collection, email: str) -> bool:
    return collection.find_one({'email': email}) is not None

# Create a temporary user entry
def create_temp_user(collection: Collection, user_details: dict):
    collection.insert_one(user_details)

# Retrieve the most recent temp user by email
def get_temp_user_by_email(collection: Collection, email: str):
    return collection.find_one({'email': email}, sort=[('_id', DESCENDING)])

# Create a user in the users collection
def create_user(collection: Collection, user_data: dict):
    collection.insert_one(user_data)

# Delete a temp user by email
def delete_temp_user(temp_users_collection, email: str):
    temp_users_collection.delete_many({"email": email})

