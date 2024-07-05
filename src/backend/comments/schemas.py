from datetime import datetime 
from bson import ObjectId
from pydantic import BaseModel

class CommentBase(BaseModel):
    text: str

class CommentInDB(CommentBase):
    author_id: str
    created_date: datetime

    class Config:
        orm_mode = True
        from_attributes = True

class Pagination(BaseModel):
    limit: int = 10
    skip: int = 0
