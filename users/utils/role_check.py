from fastapi import Depends, HTTPException, Request
from jose import jwt, JWTError
from utils.jwt_auth import JWT_SECRET, ALGORITHM

def get_current_user_role(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = token.split(" ")[1] if 'Bearer ' in token else token
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user_role = payload.get("role")
        if user_role is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_role
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
def get_current_user_email(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = token.split(" ")[1] if 'Bearer ' in token else token
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        # print(f"Decoded user_email from token: {user_email}")
        if user_email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_email
    except JWTError as e:
        print(f"JWTError: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user_id(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = token.split(" ")[1] if 'Bearer ' in token else token
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user_id = payload.get("id")
        # print(f"Decoded user_email from token: {user_email}")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except JWTError as e:
        print(f"JWTError: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")

    
# def get_current_user_email(request: Request):
#     token = request.cookies.get("access_token")
#     if not token:
#         raise HTTPException(status_code=401, detail="Not authenticated")

#     token = token.split(" ")[1] if 'Bearer ' in token else token
#     try:
#         payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
#         user_email = payload.get("sub")
#         if user_email is None:
#             raise HTTPException(status_code=401, detail="Invalid token")
#         return user_email
#     except JWTError:
#         raise HTTPException(status_code=401, detail="Invalid token")

def admin_required(role: str = Depends(get_current_user_role)):
    if role != "Admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
