from fastapi import FastAPI, Depends, Response, Cookie, status, Request, APIRouter, BackgroundTasks, HTTPException
from fastapi.responses import StreamingResponse
from fastapi.security import OAuth2PasswordBearer, HTTPBasic, HTTPBasicCredentials

from database import db
from schemas import *
from utils.password import *
from utils.crud import *
from utils.jwt_auth import *
from utils.email import *
from utils.role_check import admin_required, get_current_user_email
from fastapi.middleware.cors import CORSMiddleware

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

users.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBasic()

users_collection = db.users
temp_users_collection = db.temp_users
modification_history_collection = db.change_logs

# # Register route
# @users.post("/api/v1/user/register")
# async def register(user_data: UserBase):
#     if check_user_exists(users_collection, user_data.email):
#         raise HTTPException(status_code=400, detail="Email already registered.")
    
#     if check_user_exists(temp_users_collection, user_data.email):
#         temp_users_collection.delete_many({"email": user_data.email})
    
#     hashed_password = hash_password(user_data.password)
#     user_data.password = hashed_password

#     totp_secret = pyotp.random_base32()
#     totp = pyotp.TOTP(totp_secret)

#     temp_user_details = user_data.dict()
#     temp_user_details['totp_secret'] = totp_secret
#     temp_user_details['created_at'] = datetime.utcnow()

#     temp_users_collection.insert_one(temp_user_details)

#     first_totp = totp.now()

#     return {
#         "message": "Use this TOTP for 2FA verification",
#         "totp": first_totp
#     }

# # TOTP validation
# @users.post("/api/v1/user/reg-otp")
# async def validate_totp(totp_details: TOTPValidation, response: Response):
#     temp_user = get_temp_user_by_email(temp_users_collection, totp_details.email)
#     if not temp_user:
#         raise HTTPException(status_code=400, detail="Please re-register, your registration details have expired.")

#     totp_secret = temp_user['totp_secret']
#     totp = pyotp.TOTP(totp_secret)
    
#     if totp.verify(totp_details.totp, valid_window=1):
#         try:
#             temp_user.pop('created_at', None)
#             user_data = UserInDB(
#                 **temp_user, 
#                 user_id=str(uuid4()), 
#                 role=temp_user.get('role', 'User'), 
#                 created_at=datetime.now(), 
#                 last_modified_at=None,
#                 last_login=datetime.now(),
#             )
#             create_user(users_collection, user_data.dict(exclude_unset=True))

#             delete_temp_user(temp_users_collection, totp_details.email)

#             token = create_jwt(str(user_data.email), JWT_SECRET, user_data.role, True)
#             response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True, secure=False)
#             return {"message": "Login successful.", "user_email": user_data.email}
#         except DuplicateKeyError:
#             raise HTTPException(status_code=409, detail="Email already exists in the system.")
#     else:
#         delete_temp_user(temp_users_collection, totp_details.email)
#         raise HTTPException(status_code=403, detail="Wrong TOTP entered. Please re-register.")

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
    
# # 3
# @users.post('/api/v1/user/login')
# async def login(response: Response, credentials: HTTPBasicCredentials = Depends(security)):
#     username = credentials.username
#     password = credentials.password

#     user = users_collection.find_one({"email": username})
#     if not user or not verify_password(password, user['password']):
#         raise HTTPException(status_code=401, detail="Invalid credentials")

#     totp_secret = user.get('totp_secret')
#     if not totp_secret:
#         raise HTTPException(status_code=400, detail="TOTP secret not found. Please re-register.")

#     totp = pyotp.TOTP(totp_secret)
#     login_totp = totp.now()

#     return {
#         "message": "Enter TOTP to complete login",
#         "totp": login_totp
#     }

# @users.post("/api/v1/user/totp")
# async def validate_login_totp(totp_details: TOTPValidation, response: Response):
#     user = users_collection.find_one({"email": totp_details.email})
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found. Please re-register.")

#     totp_secret = user['totp_secret']
#     totp = pyotp.TOTP(totp_secret)
    
#     if totp.verify(totp_details.totp, valid_window=1):
#         try:
#             token = create_jwt(str(user['email']), user['role'], user['user_id'])
#             response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True, secure=False)

#             return {"message": "Login successful.", "user_email": user['email']}
#         except Exception as e:
#             raise HTTPException(status_code=500, detail="Internal server error.")
#     else:
#         raise HTTPException(status_code=403, detail="Wrong TOTP entered. Please re-login.")


# # 3
# @users.post('/api/v1/user/login')
# async def login(response: Response, credentials: HTTPBasicCredentials = Depends(security)):
#     username = credentials.username
#     password = credentials.password

#     user = users_collection.find_one({"email": username})
#     if not user or not verify_password(password, user['password']):
#         raise HTTPException(status_code=401, detail="Invalid credentials")

#     # Fetch the TOTP secret directly from the user's details
#     totp_secret = user.get('totp_secret')
#     if not totp_secret:
#         raise HTTPException(status_code=400, detail="TOTP secret not found. Please re-register.")

#     # Generate a new TOTP for login verification
#     totp = pyotp.TOTP(totp_secret)
#     login_totp = totp.now()

#     return {
#         "message": "Enter TOTP to complete login",
#         "totp": login_totp  # Return the current TOTP for login verification
#     }

# # 4
# @users.post("/api/v1/user/totp")
# async def validate_login_totp(totp_details: TOTPValidation, response: Response):
#     user = users_collection.find_one({"email": totp_details.email})
#     if not user:
#         raise HTTPException(status_code=404, detail="User not found. Please re-register.")

#     totp_secret = user['totp_secret']
#     totp = pyotp.TOTP(totp_secret)
    
#     if totp.verify(totp_details.totp, valid_window=1):
#         try:
#             # Log in the user and issue a JWT token
#             token = create_jwt(str(user['email']), JWT_SECRET, user['role'], True)
#             response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True, secure=False)

#             return {"message": "Login successful.", "user_email": user['email']}
#         except Exception as e:
#             raise HTTPException(status_code=500, detail="Internal server error.")
#     else:
#         raise HTTPException(status_code=403, detail="Wrong TOTP entered. Please re-login.")

# # 5.1
# @users.post("/api/v1/user/forgot-password")
# async def forgot_password(email: EmailStr, background_tasks: BackgroundTasks):
#     user = users_collection.find_one({"email": email})
#     if not user:
#         raise HTTPException(status_code=404, detail="Email not registered.")

#     otp_secret = pyotp.random_base32()
#     totp = pyotp.TOTP(otp_secret)
#     otp = totp.now()

#     temp_users_collection.update_one(
#         {"email": email},
#         {"$set": {"otp_secret": otp_secret, "created_at": datetime.utcnow()}},
#         upsert=True
#     )

#     background_tasks.add_task(send_email_otp, email, otp)

#     return {"message": "OTP sent to your email for password reset."}

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

# # 5.2
# @users.post("/api/v1/user/reset-password")
# async def reset_password(request: ResetPasswordRequest):
#     temp_user = temp_users_collection.find_one({"email": request.email})
#     if not temp_user:
#         raise HTTPException(status_code=400, detail="OTP has expired or is invalid. Please request a new OTP.")

#     otp_secret = temp_user['otp_secret']
#     totp = pyotp.TOTP(otp_secret)
    
#     if totp.verify(request.otp, valid_window=1):
#         hashed_password = hash_password(request.new_password)
#         update_result = users_collection.update_one(
#             {"email": request.email},
#             {
#                 "$set": {
#                     "password": hashed_password,
#                     "last_modified_at": datetime.utcnow()
#                 },
#                 "$push": {
#                     "modification_logs": f"Password reset on {datetime.utcnow().isoformat()}"
#                 }
#             }
#         )

#         if update_result.modified_count == 0:
#             raise HTTPException(status_code=404, detail="User not found or password already reset.")

#         # Log the password change in the modification history collection
#         log_entry = ModificationHistory(log=f"Password for {request.email} was reset.").dict()
#         modification_history_collection.insert_one(log_entry)

#         temp_users_collection.delete_many({"email": request.email})

#         return {"message": "Password reset successful."}
#     else:
#         raise HTTPException(status_code=403, detail="Invalid OTP. Please request a new OTP.")

@users.post("/api/v1/user/reset-password")
async def reset_password(request: ResetPasswordRequest):
    temp_user = temp_users_collection.find_one({"email": request.email})
    if not temp_user:
        raise HTTPException(status_code=400, detail="OTP has expired or is invalid. Please request a new OTP.")

    otp_secret = temp_user['otp_secret']
    totp = pyotp.TOTP(otp_secret)
    
    if totp.verify(request.otp, valid_window=1):
        hashed_password = hash_password(request.new_password)
        update_result = users_collection.update_one(
            {"email": request.email},
            {
                "$set": {
                    "password": hashed_password,
                    "last_modified_at": datetime.utcnow()
                },
                "$push": {
                    "modification_logs": f"Password reset on {datetime.utcnow().isoformat()}"
                }
            }
        )

        if update_result.modified_count == 0:
            raise HTTPException(status_code=404, detail="User not found or password already reset.")

        # Log the password change in the modification history collection
        log_entry = ModificationHistory(log=f"Password for {request.email} was reset.").dict()
        modification_history_collection.insert_one(log_entry)

        temp_users_collection.delete_many({"email": request.email})

        return {"message": "Password reset successful."}
    else:
        raise HTTPException(status_code=403, detail="Invalid OTP. Please request a new OTP.")

    
# @users.get("/api/v1/user/curr")
# async def curr():
#     return {"hello": "World"}

# @users.get("/api/v1/user/current-user")
# async def get_current_user(request: Request):

#     return {"hello": "World"}
    # print(f"Decoded user_email from token: {user_email}")

    # if not user_email:
    #     raise HTTPException(status_code=400, detail="Invalid token payload.")

    # print(f"Querying users_collection with email: {user_email}")
    # user = users_collection.find_one({"email": user_email})
    # print(f"Found user: {user}")

    # if not user:
    #     raise HTTPException(status_code=404, detail="User not found.")

    # return {
    #     "user_id": user['user_id'],
    #     "email": user['email'],
    #     "first_name": user['first_name'],
    #     "last_name": user['last_name'],
    #     "role": user['role'],
    #     "created_at": user['created_at'],
    #     "last_modified_at": user['last_modified_at'],
    #     "last_login": user['last_login']
    # }

@users.post("/api/v1/user/logout")
async def logout(response: Response):
    response.delete_cookie(key="access_token")
    return {"message": "Logout successful"}

    

# # login route with 2fa - in specs
# @users.post('/login')
# # @users.post('/api/v1/user/login')
# async def login(response: Response, credentials: HTTPBasicCredentials = Depends(security)):
#     username = credentials.username
#     password = credentials.password

#     user = users_collection.find_one({"email": username})
#     if not user or not verify_password(password, user['password']):
#         raise HTTPException(status_code=401, detail="Invalid credentials")

#     if 'totp_secret' not in user:
#         # If it's the first time login, user should register for 2FA
#         totp_secret = pyotp.random_base32()
#         uri = pyotp.TOTP(totp_secret).provisioning_uri(name=user['email'], issuer_name="YourAppName")
#         img = qrcode.make(uri)
#         buf = BytesIO()
#         img.save(buf)
#         buf.seek(0)
#         users_collection.update_one({"_id": user["_id"]}, {"$set": {"totp_secret": totp_secret}})
#         return StreamingResponse(buf, media_type="image/png")

#     # For subsequent logins, validate the temporary token and 2FA key
#     totp_details = TOTPValidation(email=username, totp=request.headers.get("X-TOTP"))
#     totp = pyotp.TOTP(user['totp_secret'])
#     if not totp.verify(totp_details.totp):
#         raise HTTPException(status_code=403, detail="Invalid TOTP")

#     role = user.get('role', 'unassigned')
#     token = create_jwt(str(user['_id']), JWT_SECRET, role, True)

#     users_collection.update_one(
#         {"_id": user['_id']},
#         {"$set": {"last_login": datetime.utcnow()}}
#     )

#     # Set the JWT token as a cookie
#     response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True, secure=False)

#     return {"message": "Login successful", "user_email": user['email'], "role": role}





























