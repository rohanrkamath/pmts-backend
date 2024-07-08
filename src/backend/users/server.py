from fastapi import FastAPI, Depends, Response, Cookie, status, Request, APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, HTTPBasic, HTTPBasicCredentials

from database import db, log_collection
from schemas import *
from utils.password import *
from utils.crud import *
from utils.jwt_auth import *
from utils.email import *
from utils.role_check import admin_required, get_current_user_email
from utils.logs import log_change 

from bson import ObjectId
from bson.errors import InvalidId
from pymongo import DESCENDING
from pymongo.errors import DuplicateKeyError
import pyotp
import qrcode
from jose import jwt, JWTError
from passlib.context import CryptContext

from datetime import datetime, timedelta
from io import BytesIO

users = FastAPI()

security = HTTPBasic()

users_collection = db.users
temp_users_collection = db.temp_users
modification_history_collection = log_collection.modification_logs

# Logging service URL {need to change port according to the docker compose file}
# LOGGING_SERVICE_URL = "http://logging_service:8000/log/"
# 1
@users.get("/api/v1/users", response_model=List[UserInDB])
async def get_all_users(role: str = Depends(admin_required)):
    users = list(users_collection.find())
    for user in users:
        user['user_id'] = str(user['user_id'])  
    return users
 
@users.get("/api/v1/user/current-user")
async def get_current_user(request: Request, user_email:str = Depends(get_current_user_email)):
    print(f"Decoded user_email from token: {user_email}")

    if not user_email:
        raise HTTPException(status_code=400, detail="Invalid token payload.")

    print(f"Querying users_collection with email: {user_email}")
    user = users_collection.find_one({"email": user_email})
    print(f"Found user: {user}")

    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    return {
        "user_id": user['user_id'],
        "email": user['email'],
        "first_name": user['first_name'],
        "last_name": user['last_name'],
        "role": user['role'],
        "created_at": user['created_at'],
        "last_modified_at": user['last_modified_at'],
        "last_login": user['last_login']
    }

# 2
@users.get("/api/v1/user/{user_id}", response_model=UserInDB)
async def get_user_by_id(user_id: str, current_user_email: str = Depends(get_current_user_email)):
    try:
        user = users_collection.find_one({"user_id": user_id})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except InvalidId:
        raise HTTPException(status_code=400, detail="Invalid user ID format")

@users.post('/api/v1/user/login')
async def login(response: Response, credentials: HTTPBasicCredentials = Depends(security)):
    username = credentials.username
    password = credentials.password

    user = users_collection.find_one({"email": username})
    if not user or not verify_password(password, user['password']):
        print("password not verified.")
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.get('two_fa_enabled', False):
    
        # First-time login, generate QR code for 2FA setup
        totp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(totp_secret)

        users_collection.update_one(
            {"_id": user["_id"]},
            {"$set": {"totp_secret": totp_secret, "two_fa_enabled": True}}
        )

        uri = totp.provisioning_uri(name=user['email'], issuer_name="YourAppName")
        img = qrcode.make(uri)
        buf = BytesIO()
        img.save(buf)
        buf.seek(0)
        
        return StreamingResponse(buf, media_type="image/png")

    else:
        # Subsequent logins, generate TOTP
        totp_secret = user['totp_secret']
        totp = pyotp.TOTP(totp_secret)
        login_totp = totp.now()
        return {
            "message": "Enter TOTP to complete login",
            # "totp": login_totp
        }

# TOTP validation route
@users.post("/api/v1/user/totp")
async def validate_login_totp(totp_details: TOTPValidation, response: Response):
    user = users_collection.find_one({"email": totp_details.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found. Please re-register.")

    totp_secret = user['totp_secret']
    totp = pyotp.TOTP(totp_secret)
    
    if totp.verify(totp_details.totp, valid_window=1):
        try:
            token = create_jwt(str(user['email']), user['role'], user['user_id'])
            response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True, secure=False)

            users_collection.update_one(
                {"_id": user["_id"]},
                {"$set": {"two_fa_enabled": True}}
            )

            return {"message": "Login successful.", "user_email": user['email']}
        except Exception as e:
            raise HTTPException(status_code=500, detail="Internal server error.")
    else:
        raise HTTPException(status_code=403, detail="Wrong TOTP entered. Please re-login.")

@users.post("/api/v1/user/forgot-password")
async def forgot_password(request: ForgotPasswordRequest, background_tasks: BackgroundTasks):
    user = users_collection.find_one({"email": request.email})
    if not user:
        raise HTTPException(status_code=404, detail="Email not registered.")

    otp_secret = pyotp.random_base32()
    totp = pyotp.TOTP(otp_secret)
    otp = totp.now()

    temp_users_collection.update_one(
        {"email": request.email},
        {"$set": {"otp_secret": otp_secret, "created_at": datetime.utcnow()}},
        upsert=True
    )

    background_tasks.add_task(send_email_otp, request.email, otp)

    return {"message": "OTP sent to your email for password reset."}

# update rout for users
@users.post("/api/v1/user/reset-password")
async def reset_password(request: ResetPasswordRequest):
    temp_user = temp_users_collection.find_one({"email": request.email})
    if not temp_user:
        raise HTTPException(status_code=400, detail="OTP has expired or is invalid. Please request a new OTP.")

    otp_secret = temp_user['otp_secret']
    totp = pyotp.TOTP(otp_secret)

    if totp.verify(request.otp, valid_window=1):
        user = users_collection.find_one({"email": request.email})
        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        original_data = {"password": user["password"]}
        hashed_password = hash_password(request.new_password)

        update_result = users_collection.update_one(
            {"email": request.email},
            {
                "$set": {
                    "password": hashed_password,
                    "last_modified_at": datetime.utcnow()
                }
            }
        )

        if update_result.modified_count == 0:
            raise HTTPException(status_code=404, detail="User not found or password already reset.")

        # Log the password change in the modification history collection
        log_id = log_change(
            service="users",
            location=str(user["_id"]),
            modified_by=str(user["_id"]),
            original_data=original_data,
            updated_data={"password": hashed_password},
            log_text=f"Password for {request.email} was reset."
        )

        if log_id:
            users_collection.update_one(
                {"email": request.email},
                {"$push": {"modification_logs": log_id}}
            )

        temp_users_collection.delete_many({"email": request.email})

        return {"message": "Password reset successful."}
    else:
        raise HTTPException(status_code=403, detail="Invalid OTP. Please request a new OTP.")

@users.post("/api/v1/user/logout")
async def logout(response: Response):
    response.delete_cookie(key="access_token")
    return {"message": "Logout successful"}





























