"""
Admin Routers - Admin API endpoints

Provides endpoints for:
- GET /me - Get current admin profile (access token auth)
- POST /register - Register new admin
- GET /{admin_id} - Get admin by ID (public, rate limited)
- PUT /me - Update current admin profile
"""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.auth.auth_services import get_current_admin_token
from backend.admins.admin_models import AdminRegisterRequest, AdminResponse, AdminUpdateRequest
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


@router.put("/me", response_model=AdminResponse)
async def update_current_admin_profile(
    body: AdminUpdateRequest,
    current_admin: dict = Depends(get_current_admin_token),
) -> AdminResponse:
    """
    Update current authenticated admin's profile.
    Requires access token authentication (Bearer token).
    """
    try:
        updated_admin = await admin_service.update_admin(current_admin["admin_id"], body)
        if not updated_admin:
            raise ValueError("Admin not found")
        return admin_service.build_admin_response(updated_admin, "Admin profile updated successfully")
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


# ================== Public Endpoints ==================

@router.post("/register", response_model=AdminResponse)
async def register_admin(body: AdminRegisterRequest) -> AdminResponse:
    """
    Register a new admin.
    No authentication required (for initial setup).
    """
    try:
        return await admin_service.create_admin_response(body)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
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
