"""
Admin Routers - Admin API endpoints

Provides endpoints for:
- GET /me - Get current admin profile (access token auth)
- POST /register - Register new admin
- GET /{admin_id} - Get admin by ID (public, rate limited)
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.auth.auth_services import get_current_admin_token
from backend.admins.admin_models import AdminRegisterRequest, AdminResponse
from backend.admins.admin_services import admin_service

router = APIRouter(prefix="/admins", tags=["admins"])

# Rate limiter instance - will be initialized with app.state.limiter in main.py
limiter = Limiter(key_func=get_remote_address)


# ================== Authenticated Admin Endpoints ==================

@router.get("/me", response_model=AdminResponse)
async def get_current_admin_profile(
    current_admin: dict = Depends(get_current_admin_token),
) -> AdminResponse:
    """
    Get current authenticated admin's profile.
    Requires access token authentication (Bearer token).
    """
    return admin_service.build_admin_profile_from_dict(current_admin)


# ================== Public Endpoints ==================

@router.post("/register", response_model=AdminResponse)
async def register_admin(body: AdminRegisterRequest) -> AdminResponse:
    """
    Register a new admin.
    Requires email to be whitelisted in admin_whitelist table.
    Returns 403 Forbidden if email is not whitelisted.
    Returns 400 Bad Request if email already exists.
    """
    try:
        return await admin_service.create_admin_response(body)
    except ValueError as e:
        error_message = str(e)
        # Return 403 for whitelist errors, 400 for other validation errors
        if "not whitelisted" in error_message.lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=error_message,
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_message,
        )


# ================== Public Endpoints (Rate Limited) ==================

@router.get("/{admin_id}")
@limiter.limit("60/minute")
async def get_admin_by_id(
    request: Request,
    admin_id: str,
) -> dict:
    """
    Get admin by ID.
    Public endpoint with rate limiting (60 requests per minute per IP).
    """
    try:
        return await admin_service.get_admin_by_id_response(admin_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
