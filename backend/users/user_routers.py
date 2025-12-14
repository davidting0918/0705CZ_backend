"""
User Routers - User API endpoints

Provides endpoints for:
- GET /me - Get current user profile (session auth)
- POST /register - Register new user
- GET /{user_id} - Get user by ID (public, rate limited)
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.auth.auth_services import get_current_user_session
from backend.users.user_models import UserRegisterRequest, UserResponse
from backend.users.user_services import user_service

router = APIRouter(prefix="/users", tags=["users"])

# Rate limiter instance - will be initialized with app.state.limiter in main.py
limiter = Limiter(key_func=get_remote_address)


# ================== Authenticated User Endpoints ==================


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: dict = Depends(get_current_user_session),
) -> UserResponse:
    """
    Get current authenticated user's profile.
    Requires session authentication (HTTP-only cookie).
    """
    return user_service.build_user_profile_from_dict(current_user)


# ================== Public Endpoints ==================


@router.post("/register", response_model=UserResponse)
async def register_user(body: UserRegisterRequest) -> UserResponse:
    """
    Register a new user.
    No authentication required.
    """
    try:
        return await user_service.create_user_response(body)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )


# ================== Public Endpoints (Rate Limited) ==================


@router.get("/{user_id}")
@limiter.limit("60/minute")
async def get_user_by_id(
    request: Request,
    user_id: str,
) -> dict:
    """
    Get user by ID.
    Public endpoint with rate limiting (60 requests per minute per IP).
    """
    try:
        return await user_service.get_user_by_id_response(user_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
