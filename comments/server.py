from fastapi import Depends, FastAPI, HTTPException, Request
from typing import List
from datetime import datetime

from database import db
from schemas import *
from utils.role_check import user_required, admin_required

comments = FastAPI()

comments_collection = db["comments"]

@comments.post('/api/v1/comment')
async def post_comment(commentData: CommentBase, role: str = Depends(user_required)):

    comment_data = commentData.dict()
    comment_data['author_id'] = role 
    comment_data['created_date'] = datetime.now()
    result = comments_collection.insert_one(comment_data)

    comment_data['_id'] = str(result.inserted_id)
    return comment_data

@comments.get("/api/v1/comments", response_model=List[CommentInDB])
async def get_all_comment(pagination: Pagination = Depends(), role: str = Depends(admin_required)):
    comments = comments_collection.find().skip(pagination.skip).limit(pagination.limit)
    return list(comments)
