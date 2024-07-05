from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel, Field, EmailStr
from typing import List, Optional
from datetime import datetime
from bson import ObjectId
import pymongo

from database import db
from schemas import *
from utils.role_check import admin_required

projects = FastAPI()

projects_collection = db.projects

# Route to get all projects with pagination
@projects.get("/api/v1/project", response_model=List[ProjectInDB])
async def get_all_projects(pagination: Pagination = Depends(), role: str = Depends(admin_required)):
    projects = projects_collection.find().skip(pagination.skip).limit(pagination.limit)
    return list(projects)

# Route to get a project by id
@projects.get("/api/v1/project/{project_id}", response_model=ProjectInDB)
async def get_project_by_id(project_id: str, role: str = Depends(admin_required)):
    try:
        project = projects_collection.find_one({"_id": ObjectId(project_id)})
        if not project:
            raise HTTPException(status_code=404, detail="Project not found")
        return project
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Route to create a new project
@projects.post("/api/v1/project", response_model=ProjectInDB)
async def create_project(project: ProjectCreate, role: str = Depends(admin_required)):
    project_data = project.dict()
    projects_collection.insert_one(project_data)
    return project_data

# patch for an existing project
@projects.patch("/api/v1/project/{project_id}", response_model=ProjectInDB)
async def update_project(project_id: str, project: ProjectUpdate, role: str = Depends(admin_required)):
    existing_project = projects_collection.find_one({"_id": ObjectId(project_id)})
    if not existing_project:
        raise HTTPException(status_code=404, detail="Project not found")

    update_data = {k: v for k, v in project.dict().items() if v is not None}

    if update_data:
        projects_collection.update_one(
            {"_id": ObjectId(project_id)},
            {"$set": update_data}
        )

    updated_project = projects_collection.find_one({"_id": ObjectId(project_id)})
    updated_project["id"] = str(updated_project["_id"])
    del updated_project["_id"]

    return ProjectInDB(**updated_project)

# @projects.patch("/api/v1/project/{project_id}/title")
# async def update_project_title(project_id: str, update: UpdateTitle, role: str = Depends(admin_required)):
#     result = projects_collection.update_one(
#         {"_id": ObjectId(project_id)},
#         {"$set": {"title": update.title}}
#     )
#     if result.matched_count == 0:
#         raise HTTPException(status_code=404, detail="Project not found")
#     return {"message": "Title updated successfully"}

# @projects.patch("/api/v1/project/{project_id}/description")
# async def update_project_description(project_id: str, update: UpdateDescription, role: str = Depends(admin_required)):
#     result = projects_collection.update_one(
#         {"_id": ObjectId(project_id)},
#         {"$set": {"description": update.description}}
#     )
#     if result.matched_count == 0:
#         raise HTTPException(status_code=404, detail="Project not found")
#     return {"message": "Description updated successfully"}

# @projects.patch("/api/v1/project/{project_id}/start_date")
# async def update_project_start_date(project_id: str, update: UpdateStartDate, role: str = Depends(admin_required)):
#     result = projects_collection.update_one(
#         {"_id": ObjectId(project_id)},
#         {"$set": {"start_date": update.start_date}}
#     )
#     if result.matched_count == 0:
#         raise HTTPException(status_code=404, detail="Project not found")
#     return {"message": "Start date updated successfully"}

# @projects.patch("/api/v1/project/{project_id}/end_date")
# async def update_project_end_date(project_id: str, update: UpdateEndDate, role: str = Depends(admin_required)):
#     result = projects_collection.update_one(
#         {"_id": ObjectId(project_id)},
#         {"$set": {"end_date": update.end_date}}
#     )
#     if result.matched_count == 0:
#         raise HTTPException(status_code=404, detail="Project not found")
#     return {"message": "End date updated successfully"}

# @projects.patch("/api/v1/project/{project_id}/status")
# async def update_project_status(project_id: str, update: UpdateStatus, role: str = Depends(admin_required)):
#     result = projects_collection.update_one(
#         {"_id": ObjectId(project_id)},
#         {"$set": {"status": update.status}}
#     )
#     if result.matched_count == 0:
#         raise HTTPException(status_code=404, detail="Project not found")
#     return {"message": "Status updated successfully"}

# @projects.patch("/api/v1/project/{project_id}/team_members")
# async def update_project_team_members(project_id: str, update: UpdateTeamMembers, role: str = Depends(admin_required)):
#     result = projects_collection.update_one(
#         {"_id": ObjectId(project_id)},
#         {"$set": {"team_members": update.team_members}}
#     )
#     if result.matched_count == 0:
#         raise HTTPException(status_code=404, detail="Project not found")
#     return {"message": "Team members updated successfully"}

# @projects.patch("/api/v1/project/{project_id}/comment_ids")
# async def update_project_comment_ids(project_id: str, update: UpdateCommentIds, role: str = Depends(admin_required)):
#     result = projects_collection.update_one(
#         {"_id": ObjectId(project_id)},
#         {"$set": {"comment_ids": update.comment_ids}}
#     )
#     if result.matched_count == 0:
#         raise HTTPException(status_code=404, detail="Project not found")
#     return {"message": "Comment IDs updated successfully"}

# x = dict()
# x['project_id'] = "fwvcw"
# x['team member'] = "cce" # if statement