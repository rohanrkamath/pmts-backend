from urllib import response
from fastapi import FastAPI, HTTPException, Depends, status
from typing import List, Optional
from datetime import datetime
from bson import ObjectId
import pymongo
import re

from database import db
from schemas import *
from utils.role_check import admin_required, user_required

tasks = FastAPI()
tasks_collection = db["tasks"]

@tasks.post("/api/v1/task", response_model=TaskResponse)
async def create_task(task: TaskBase, role: str = Depends(user_required)):
    task_data = task.dict()
    task_data["created_at"] = datetime.utcnow()
    task_data["_id"] = ObjectId()

    result = tasks_collection.insert_one(task_data)

    if not result.inserted_id:
        raise HTTPException(status_code=500, detail="Task creation failed")

    created_task = tasks_collection.find_one({"_id": result.inserted_id})

    created_task["id"] = str(created_task["_id"])
    del created_task["_id"]

    # If task is a root node (no parent path), return only the created task
    if not task.path:
        response = TaskResponse(
            tasks_on_same_level=[TaskInDB(**created_task)]
        )
        return response

    # Determine the regex pattern for finding siblings
    parent_path = task.path
    regex_pattern = f"^{parent_path}(/[^/]+)?$"

    # Find siblings using the regex pattern
    siblings_cursor = tasks_collection.find({"path": {"$regex": regex_pattern}})
    siblings = list(siblings_cursor)
    for sibling in siblings:
        sibling["id"] = str(sibling["_id"])
        del sibling["_id"]

    # Ensure no duplicates by checking if the created task is already in siblings
    if not any(sibling["id"] == created_task["id"] for sibling in siblings):
        siblings.append(created_task)

    siblings_model = [TaskInDB(**sibling) for sibling in siblings]

    return task_data
    # response = TaskResponse(
    #     tasks_on_same_level=siblings_model
    # )

    # return response


# async def create_task(task: TaskBase, role: str = Depends(user_required)):
#     task_data = task.dict()
#     task_data["created_at"] = datetime.utcnow()
#     task_data["_id"] = ObjectId()

#     result = tasks_collection.insert_one(task_data)

#     if not result.inserted_id:
#         raise HTTPException(status_code=500, detail="Task creation failed")

#     created_task = tasks_collection.find_one({"_id": result.inserted_id})

#     created_task["id"] = str(created_task["_id"])
#     del created_task["_id"]

#     # If task is a root node (no parent path), return only the created task
#     if not task.path:
#         response = TaskResponse(
#             tasks_on_same_level=[TaskInDB(**created_task)]
#         )
#         return response

#     # Determine the regex pattern for finding siblings
#     parent_path = task.path
#     regex_pattern = f"^{parent_path}(/[^/]+)?$"

#     # Find siblings using the regex pattern
#     siblings_cursor = tasks_collection.find({"path": {"$regex": regex_pattern}})
#     siblings = list(siblings_cursor)
#     for sibling in siblings:
#         sibling["id"] = str(sibling["_id"])
#         del sibling["_id"]

#     # Ensure no duplicates by checking if the created task is already in siblings
#     if not any(sibling["id"] == created_task["id"] for sibling in siblings):
#         siblings.append(created_task)

#     siblings_model = [TaskInDB(**sibling) for sibling in siblings]

#     response = TaskResponse(
#         tasks_on_same_level=siblings_model
#     )

#     return response

# Get a task by ID
@tasks.get("/api/v1/task/{task_id}", response_model=TaskInDB)
async def get_task_by_id(task_id: str, role: str = Depends(admin_required)):
    task = tasks_collection.find_one({"_id": ObjectId(task_id)})
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # Convert ObjectId to string for the task
    task["id"] = str(task["_id"])
    del task["_id"]

    return TaskInDB(**task)

# Get all tasks with pagination and filtering
@tasks.get("/api/v1/task", response_model=List[TaskInDB])
async def get_all_tasks(role: str = Depends(admin_required)):
    tasks_cursor = tasks_collection.find()
    tasks_list = list(tasks_cursor)
    
    # Convert ObjectId to string for each task
    for task in tasks_list:
        task["id"] = str(task["_id"])
        del task["_id"]
    
    return [TaskInDB(**task) for task in tasks_list]

# # Get all tasks with pagination and filtering
# @tasks.get("/api/v1/task", response_model=List[TaskInDB])
# async def get_all_tasks(pagination: Pagination = Depends(), role: str = Depends(admin_required)):
#     tasks = tasks_collection.find().skip(pagination.skip).limit(pagination.limit)
#     return list(tasks)

# Update a task by ID
@tasks.patch("/api/v1/task/{task_id}", response_model=TaskInDB)
async def update_task(task_id: str, task: TaskUpdate, role: str = Depends(user_required)):
    existing_task = tasks_collection.find_one({"_id": ObjectId(task_id)})
    if not existing_task:
        raise HTTPException(status_code=404, detail="Task not found")

    update_data = {k: v for k, v in task.dict().items() if v is not None}
    changed_fields = {}
    for field, value in update_data.items():
        if existing_task.get(field) != value:
            changed_fields[field] = value

    if changed_fields:
        changed_fields["last_modified_at"] = datetime.utcnow()
        result = tasks_collection.update_one(
            {"_id": ObjectId(task_id)},
            {"$set": changed_fields}
        )
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Task not found")
    
    updated_task = tasks_collection.find_one({"_id": ObjectId(task_id)})
    updated_task["id"] = str(updated_task["_id"])
    del updated_task["_id"]

    return TaskInDB(**updated_task)

