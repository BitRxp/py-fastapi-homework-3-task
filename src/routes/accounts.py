from datetime import datetime, timezone

from fastapi import APIRouter, Depends, status, HTTPException
from sqlalchemy import select, delete
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel,
)
from exceptions import BaseSecurityError
from security.interfaces import JWTAuthManagerInterface

from exceptions.security import TokenExpiredError, InvalidTokenError
from schemas.accounts import (
    MessageResponseSchema,
    UserActivationRequestSchema,
    UserRegistrationRequestSchema,
    PasswordResetRequestSchema,
    TokenRefreshResponseSchema,
    TokenRefreshRequestSchema,
    PasswordResetCompleteRequestSchema,
    UserRegistrationResponseSchema,
    UserLoginResponseSchema,
    UserLoginRequestSchema,
)

router = APIRouter()


def _as_aware_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@router.post(
    "/register/",
    response_model=UserRegistrationResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    payload: UserRegistrationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    email = payload.email.lower()

    existing = await db.scalar(select(UserModel).where(UserModel.email == email))
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A user with this email {email} already exists.",
        )

    group = await db.scalar(
        select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER)
    )
    if not group:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Default user group not configured.",
        )

    user = UserModel.create(
        email=email, raw_password=payload.password, group_id=group.id
    )
    db.add(user)
    await db.flush()

    activation = ActivationTokenModel(user_id=user.id)
    db.add(activation)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during user creation.",
        )

    return UserRegistrationResponseSchema(id=user.id, email=user.email)


@router.post(
    "/activate/", response_model=MessageResponseSchema, status_code=status.HTTP_200_OK
)
async def activate(
    payload: UserActivationRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    email = payload.email.lower()

    user = await db.scalar(select(UserModel).where(UserModel.email == email))
    if not user:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    token = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.user_id == user.id,
            ActivationTokenModel.token == payload.token,
        )
    )
    if not token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    now_utc = datetime.now(timezone.utc)
    if _as_aware_utc(token.expires_at) <= now_utc:
        await db.delete(token)
        await db.commit()
        raise HTTPException(
            status_code=400, detail="Invalid or expired activation token."
        )

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return {"message": "User account activated successfully."}


@router.post(
    "/password-reset/request/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def password_reset_request(
    payload: PasswordResetRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    email = payload.email.lower()
    user = await db.scalar(select(UserModel).where(UserModel.email == email))

    if user and user.is_active:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        db.add(PasswordResetTokenModel(user_id=user.id))
        await db.commit()

    return {
        "message": "If you are registered,"
        " you will receive an email"
        " with instructions."
    }


@router.post(
    "/reset-password/complete/",
    response_model=MessageResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def reset_password_complete(
    payload: PasswordResetCompleteRequestSchema,
    db: AsyncSession = Depends(get_db),
):
    email = payload.email.lower()

    user = await db.scalar(select(UserModel).where(UserModel.email == email))
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    reset_token = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
            PasswordResetTokenModel.token == payload.token,
        )
    )

    if not reset_token:
        await db.execute(
            delete(PasswordResetTokenModel).where(
                PasswordResetTokenModel.user_id == user.id
            )
        )
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    if _as_aware_utc(reset_token.expires_at) <= datetime.now(timezone.utc):
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    # IMPORTANT: the model's setter validates strength and HASHES the password
    user.password = payload.password # setter validates and HASHES the password

    await db.delete(reset_token)

    try:
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred while resetting the password.",
        )

    return {"message": "Password reset successfully."}


@router.post(
    "/login/",
    response_model=UserLoginResponseSchema,
    status_code=status.HTTP_201_CREATED,
)
async def login(
    payload: UserLoginRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
    settings: BaseAppSettings = Depends(get_settings),
):
    email = payload.email.lower()

    user = await db.scalar(select(UserModel).where(UserModel.email == email))
    if not user or not user.verify_password(payload.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    refresh_token = jwt_manager.create_refresh_token({"user_id": user.id})

    try:
        refresh_model = RefreshTokenModel.create(
            user_id=user.id,
            days_valid=getattr(settings, "REFRESH_TOKEN_DAYS", 7),
            token=refresh_token,
        )
        db.add(refresh_model)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while processing the request."
        )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
    }


@router.post(
    "/refresh/",
    response_model=TokenRefreshResponseSchema,
    status_code=status.HTTP_200_OK,
)
async def refresh(
    payload: TokenRefreshRequestSchema,
    db: AsyncSession = Depends(get_db),
    jwt_manager: JWTAuthManagerInterface = Depends(get_jwt_auth_manager),
):
    try:
        data = jwt_manager.decode_refresh_token(payload.refresh_token)
    except TokenExpiredError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except InvalidTokenError as e:
        raise HTTPException(status_code=400, detail=str(e))

    user_id = data.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="Invalid token.")

    db_token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == payload.refresh_token
        )
    )
    if not db_token:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = await db.scalar(select(UserModel).where(UserModel.id == user_id))
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token({"user_id": user.id})
    return {"access_token": access_token, "token_type": "bearer"}
