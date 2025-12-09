"""
User Routers - User API endpoints

Provides endpoints for:
- GET /me - Get current user profile (session auth)
- POST /register - Register new user
- GET /{user_id} - Get user by ID (api_key auth)
"""

from fastapi import APIRouter, Depends, HTTPException, status

from backend.auth.auth_services import get_current_user_session, verify_api_key
from backend.users.user_models import (
    UserProfileResponse,
    UserPublicResponse,
    UserRegisterRequest,
    UserResponse,
)
from backend.users.user_services import user_service

router = APIRouter(prefix="/users", tags=["users"])


# ================== Authenticated User Endpoints ==================

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: dict = Depends(get_current_user_session),
) -> UserResponse:
    """
    Get current authenticated user's profile.
    Requires session authentication (HTTP-only cookie).
    """
    return UserResponse(
        status=1,
        message="User profile retrieved",
        data=UserProfileResponse(
            user_id=current_user["user_id"],
            email=current_user["email"],
            name=current_user["name"],
            phone=current_user.get("phone"),
            address=current_user.get("address"),
            photo_url=current_user.get("photo_url"),
            is_active=current_user["is_active"],
            is_verified=current_user["is_verified"],
            created_at=current_user["created_at"],
            updated_at=current_user["updated_at"],
        ),
    )


# ================== Public Endpoints ==================

@router.post("/register", response_model=UserResponse)
async def register_user(body: UserRegisterRequest) -> UserResponse:
    """
    Register a new user.
    No authentication required.
    """
    try:
        user = await user_service.create_user(body)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return UserResponse(
        status=1,
        message="User registered successfully",
        data=UserProfileResponse(
            user_id=user["user_id"],
            email=user["email"],
            name=user["name"],
            phone=user.get("phone"),
            address=user.get("address"),
            photo_url=user.get("photo_url"),
            is_active=user["is_active"],
            is_verified=user["is_verified"],
            created_at=user["created_at"],
            updated_at=user["updated_at"],
        ),
    )


# ================== API Key Protected Endpoints ==================

@router.get("/{user_id}")
async def get_user_by_id(
    user_id: str,
    api_key: dict = Depends(verify_api_key),
) -> dict:
    """
    Get user by ID.
    Requires API key authentication (X-API-Key header).
    """
    user = await user_service.get_user_by_id(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return {
        "status": 1,
        "message": "User retrieved",
        "data": UserPublicResponse(
            user_id=user["user_id"],
            name=user["name"],
            photo_url=user.get("photo_url"),
        ).model_dump(),
    }

