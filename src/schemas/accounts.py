import re

from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    def password_complexity(cls, password: str) -> str:
        return accounts_validators.validate_password_strength(password)


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str

    @field_validator("password")
    def password_complexity(cls, v: str):
        return accounts_validators.validate_password_strength(v)


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    token_type: str = "bearer"


class MessageResponseSchema(BaseModel):
    message: str
