from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime
# from bson import ObjectId

class ProjectBase(BaseModel):
    title: str
    description: str
    start_date: datetime
    end_date: datetime
    status: str
    team_members: List[str]  # List of user ids
    comment_ids: List[str]  # List of comment ids

class ProjectCreate(ProjectBase):
    pass

class ProjectUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    status: Optional[str] = None
    team_members: Optional[List[str]] = None
    comment_ids: Optional[List[str]] = None

class ProjectInDB(ProjectBase):
    actual_start_date: Optional[datetime] = None
    actual_end_date: Optional[datetime] = None

    class Config:
        from_attributes = True

class Pagination(BaseModel):
    limit: int = 10
    skip: int = 0

# patch request schema for all the requests 

class UpdateTitle(BaseModel):
    title: str

class UpdateDescription(BaseModel):
    description: str

class UpdateStartDate(BaseModel):
    start_date: datetime

class UpdateEndDate(BaseModel):
    end_date: datetime

class UpdateStatus(BaseModel):
    status: str

class UpdateTeamMembers(BaseModel):
    team_members: List[str]

class UpdateCommentIds(BaseModel):
    comment_ids: List[str]
