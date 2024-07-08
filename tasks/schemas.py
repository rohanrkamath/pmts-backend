from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional, Dict, Any
from datetime import datetime
from bson import ObjectId

# Task Schemas
class TaskBase(BaseModel):
    project_id: str
    title: str
    description: str
    assignee: Optional[List[str]] = None
    status: str
    priority: str
    path: Optional[str] = ""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    actual_start_date: Optional[datetime] = None
    actual_end_date: Optional[datetime] = None

class TaskUpdate(BaseModel):
    project_id: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    assignee: Optional[List[str]] = None
    status: Optional[str] = None
    priority: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    actual_start_date: Optional[datetime] = None
    actual_end_date: Optional[datetime] = None

class TaskInDB(TaskBase):
    id: str
    created_at: datetime
    last_modified_at: Optional[datetime] = None
    subtasks: Optional[List[Dict[str, Any]]] = []
    comment_ids: Optional[List[str]] = []
    modification_logs: Optional[List[str]] = []

    class Config:
        orm_mode = True
        arbitrary_types_allowed = True

# class TaskInDB(TaskBase):
#     id: str = Field(default_factory=lambda: str(ObjectId()))
#     created_at: datetime
#     last_modified_at: Optional[datetime] = None
#     subtasks: Optional[List[Dict[str, Any]]] = []

#     class Config:
#         orm_mode = True
#         arbitrary_types_allowed = True

class TaskResponse(BaseModel):
    tasks_on_same_level: List[TaskInDB]

    class Config:
        orm_mode = True
        arbitrary_types_allowed = True


class ChangeLog(BaseModel):
    task_id: str
    changes: List[dict]
    updated_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        orm_mode = True

class Pagination(BaseModel):
    limit: int = 10
    skip: int = 0
