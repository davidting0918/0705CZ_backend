"""
Auth Routers - Authentication API endpoints

Provides endpoints for:
1. Session-based login (email, Google, LINE) - for user website
2. Access token generation (email/password, Google) - for admin dashboard
3. Logout
"""

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from backend.core.security import ACCESS_TOKEN_EXPIRE_MINUTES, SESSION_COOKIE_NAME
from backend.auth.auth_models import (
    AccessTokenResponse,
    EmailLoginRequest,
    GoogleLoginRequest,
    LineLoginRequest,
    LineLoginResponse,
    SessionLoginResponse,
    UserResponse,
)
from backend.auth.auth_services import auth_service, get_current_user_session
from backend.admins.admin_models import AdminGoogleLoginRequest

router = APIRouter(prefix="/auth", tags=["auth"])


# ================== Helper Functions ==================

def set_session_cookie(response: Response, token: str) -> None:
    """
    Set HTTP-only session cookie on response.
    
    Args:
        response: FastAPI Response object
        token: Session token to set
    """
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,  # Set to True in production (HTTPS)
        samesite="lax",
        max_age=7 * 24 * 60 * 60,  # 7 days
    )


def build_user_response(user: dict) -> UserResponse:
    """
    Build UserResponse from user dict.
    
    Args:
        user: User dictionary from database
        
    Returns:
        UserResponse object
    """
    return UserResponse(
        user_id=user["user_id"],
        email=user["email"],
        name=user["name"],
        photo_url=user.get("photo_url"),
    )


def build_session_login_response(user: dict, message: str = "Login successful") -> SessionLoginResponse:
    """
    Build SessionLoginResponse from user dict.
    
    Args:
        user: User dictionary from database
        message: Success message
        
    Returns:
        SessionLoginResponse object
    """
    return SessionLoginResponse(
        status=1,
        message=message,
        data=build_user_response(user),
    )


# ================== Session-Based Authentication (User Website) ==================

@router.post("/email/login", response_model=SessionLoginResponse)
async def email_login(
    request: Request,
    response: Response,
    body: EmailLoginRequest,
) -> SessionLoginResponse:
    """
    Login with email and password.
    Creates a session and sets HTTP-only cookie.
    """
    user = await auth_service.authenticate_by_email(body.email, body.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )

    token = await auth_service.create_session_from_request(request, user["user_id"])
    set_session_cookie(response, token)
    return build_session_login_response(user, "Login successful")


@router.post("/google/user/login", response_model=SessionLoginResponse)
async def google_user_login(
    request: Request,
    response: Response,
    body: GoogleLoginRequest,
) -> SessionLoginResponse:
    """
    User Google OAuth login endpoint.
    Authenticates user via Google OAuth token and returns session cookie.
    Creates or finds user, creates session, sets HTTP-only cookie.
    """
    user = await auth_service.authenticate_google_user(body.token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google authorization",
        )

    token = await auth_service.create_session_from_request(request, user["user_id"])
    set_session_cookie(response, token)
    return build_session_login_response(user, "Google login successful")


@router.post("/google/admin/login", response_model=AccessTokenResponse)
async def google_admin_login(
    body: AdminGoogleLoginRequest,
) -> AccessTokenResponse:
    """
    Admin Google OAuth login endpoint.
    Authenticates admin via Google OAuth token and returns JWT access token.
    
    Only emails in the admin whitelist can successfully login.
    Returns 403 Forbidden if email is not whitelisted.
    Returns 401 Unauthorized if Google token is invalid.
    """
    admin = await auth_service.authenticate_admin_google(body.token)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google authorization",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jwt_token, _ = await auth_service.create_access_token_record(admin["admin_id"])

    return AccessTokenResponse(
        access_token=jwt_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        message="Admin Google login successful",
    )


@router.post("/line/login", response_model=LineLoginResponse)
async def line_login_initiate(body: LineLoginRequest) -> LineLoginResponse:
    """
    Initiate LINE OAuth login flow.
    Returns authorization URL to redirect user to LINE.
    """
    state = secrets.token_urlsafe(16)
    auth_url = auth_service.get_line_authorization_url(state, body.redirect_uri)
    
    return LineLoginResponse(authorization_url=auth_url)


@router.get("/line/callback")
async def line_login_callback(
    request: Request,
    response: Response,
    code: str,
    state: str,
) -> SessionLoginResponse:
    """
    Handle LINE OAuth callback.
    Exchanges code for token, creates/finds user, creates session.
    """
    user = await auth_service.authenticate_line_user(code)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="LINE authentication failed",
        )

    token = await auth_service.create_session_from_request(request, user["user_id"])
    set_session_cookie(response, token)
    return build_session_login_response(user, "LINE login successful")


# ================== Access Token (Staff Dashboard) ==================

@router.post("/access_token", response_model=AccessTokenResponse)
async def get_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> AccessTokenResponse:
    """
    Get JWT access token for admin dashboard.
    Uses OAuth2 password flow (username=email, password).
    Authenticates against admins table.
    
    Requires email to be whitelisted in admin_whitelist table.
    Returns 403 Forbidden if email is not whitelisted.
    Returns 401 Unauthorized if email/password is incorrect.
    """
    admin = await auth_service.authenticate_admin_by_email(form_data.username, form_data.password)
    if not admin:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jwt_token, _ = await auth_service.create_access_token_record(admin["admin_id"])

    return AccessTokenResponse(
        access_token=jwt_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        message="Access token generated successfully",
    )


# ================== Logout ==================

@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    current_user: dict = Depends(get_current_user_session),
) -> dict:
    """
    Logout current user.
    Deletes session and clears cookie.
    """
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        await auth_service.delete_session(token)

    response.delete_cookie(SESSION_COOKIE_NAME)

    return {
        "status": 1,
        "message": "Logged out successfully",
    }
