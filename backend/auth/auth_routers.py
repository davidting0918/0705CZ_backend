"""
Auth Routers - Authentication API endpoints

Provides endpoints for:
1. Session-based login (email, Google, LINE) - for user website
2. Access token generation - for staff dashboard
3. Logout
"""

import secrets
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import RedirectResponse
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

router = APIRouter(prefix="/auth", tags=["auth"])


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

    # Create session
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    token, _ = await auth_service.create_session(
        user_id=user["user_id"],
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Set HTTP-only cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,  # Set to True in production (HTTPS)
        samesite="lax",
        max_age=7 * 24 * 60 * 60,  # 7 days
    )

    return SessionLoginResponse(
        status=1,
        message="Login successful",
        data=UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            name=user["name"],
            photo_url=user.get("photo_url"),
        ),
    )


@router.post("/google/login", response_model=SessionLoginResponse)
async def google_login(
    request: Request,
    response: Response,
    body: GoogleLoginRequest,
) -> SessionLoginResponse:
    """
    Login with Google OAuth token.
    Creates or finds user, creates session, sets HTTP-only cookie.
    """
    user = await auth_service.authenticate_google_user(body.token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Google authorization",
        )

    # Create session
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    token, _ = await auth_service.create_session(
        user_id=user["user_id"],
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Set HTTP-only cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=7 * 24 * 60 * 60,
    )

    return SessionLoginResponse(
        status=1,
        message="Google login successful",
        data=UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            name=user["name"],
            photo_url=user.get("photo_url"),
        ),
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

    # Create session
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    token, _ = await auth_service.create_session(
        user_id=user["user_id"],
        ip_address=ip_address,
        user_agent=user_agent,
    )

    # Set HTTP-only cookie
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=7 * 24 * 60 * 60,
    )

    return SessionLoginResponse(
        status=1,
        message="LINE login successful",
        data=UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            name=user["name"],
            photo_url=user.get("photo_url"),
        ),
    )


# ================== Access Token (Staff Dashboard) ==================

@router.post("/access_token", response_model=AccessTokenResponse)
async def get_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> AccessTokenResponse:
    """
    Get JWT access token for staff dashboard.
    Uses OAuth2 password flow (username/password form).
    """
    user = await auth_service.authenticate_by_name(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    jwt_token, _ = await auth_service.create_access_token_record(user["user_id"])

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
