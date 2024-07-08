from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional, List
from datetime import datetime
from uuid import uuid4
import re

# user reg and login
class UserBase(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    password: str

    @field_validator('email')
    def validate_email_domain(cls, email):
        allowed_domains = ["rayvector.com"]
        domain = email.split('@')[1]
        if domain not in allowed_domains:
            raise ValueError('Email domain is not allowed.')
        return email

    @field_validator('password')
    def validate_password(cls, password):
        if not re.fullmatch(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$', password):
            raise ValueError('Password must be at least 8 characters long, include 1 uppercase letter, 1 lowercase letter, and 1 number. Special characters are not allowed.')
        return password

class UserInDB(BaseModel):
    user_id: str = str(uuid4())  # Generate a UUID4 on successful registration
    email: EmailStr
    first_name: str
    last_name: str
    password: str
    role: str = "User"
    created_at: Optional[datetime] = None
    last_modified_at: Optional[datetime] = None
    totp_secret: str
    last_login: Optional[datetime] = None
    modification_logs: Optional[List[str]] = []
    two_fa_enabled: bool = False

    class Config:
        from_attributes = True



# -------------------------------
# totp validation

class TOTPValidation(BaseModel):
    email: EmailStr
    totp: str

# -------------------------------
# forgot password

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str

    @field_validator('new_password')
    def validate_password(cls, password):
        if not re.fullmatch(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d]{8,}$', password):
            raise ValueError('Password must be at least 8 characters long, include 1 uppercase letter, 1 lowercase letter, and 1 number. Special characters are not allowed.')
        return password
    
# -------------------------------
# change logs
    
# class ModificationHistory(BaseModel):
#     log: str
#     created_at: datetime = Field(default_factory=datetime.utcnow)

#     class Config:
#         from_attributes = True