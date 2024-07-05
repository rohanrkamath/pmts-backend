from datetime import datetime, timedelta
from jose import jwt, JWTError
from fastapi import HTTPException, status

JWT_SECRET = "some_jwt_secret_not_sure_What_to_keEp99007"
ALGORITHM = "HS256"

def create_jwt(user_email: str, role: str):
    expiration = datetime.utcnow() + timedelta(hours=24)  # Token expires in 24 hours

    payload = {
        "sub": user_email,  # user email
        "iat": datetime.utcnow(),  # Issued at time
        "exp": expiration,  # Expiration time
        "role": role,  # User role
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)
    return token

def decode_jwt(token: str):
    try:
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        return decoded
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )