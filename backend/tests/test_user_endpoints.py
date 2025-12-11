"""
Integration tests for user endpoints.
"""

import pytest
from httpx import AsyncClient

from backend.tests.conftest import (
    assert_user_response_structure,
    create_test_user,
    generate_test_email,
)


# ================== POST /users/register ==================

@pytest.mark.asyncio
async def test_register_user_success(async_client: AsyncClient, clean_db):
    """Test successful user registration."""
    email = generate_test_email("user")
    
    response = await async_client.post(
        "/users/register",
        json={
            "email": email,
            "password": "TestPassword123!",
            "name": "Test User",
        },
    )
    
    assert response.status_code == 200
    data = response.json()
    assert_user_response_structure(data)
    assert data["data"]["email"] == email
    assert data["data"]["name"] == "Test User"
    assert data["data"]["is_verified"] is True
    assert "password" not in data["data"]


@pytest.mark.asyncio
async def test_register_user_with_optional_fields(async_client: AsyncClient, clean_db):
    """Test user registration with optional fields."""
    email = generate_test_email("user")
    
    response = await async_client.post(
        "/users/register",
        json={
            "email": email,
            "password": "TestPassword123!",
            "name": "Test User",
            "phone": "+1234567890",
            "address": "123 Test St, Test City",
        },
    )
    
    assert response.status_code == 200
    data = response.json()
    assert_user_response_structure(data)
    assert data["data"]["phone"] == "+1234567890"
    assert data["data"]["address"] == "123 Test St, Test City"


@pytest.mark.asyncio
async def test_register_user_duplicate_email(async_client: AsyncClient, clean_db):
    """Test user registration with duplicate email."""
    email = generate_test_email("user")
    
    # Create first user
    await create_test_user(email=email)
    
    # Try to register again
    response = await async_client.post(
        "/users/register",
        json={
            "email": email,
            "password": "TestPassword123!",
            "name": "Test User 2",
        },
    )
    
    assert response.status_code == 400
    assert "already" in response.json()["detail"].lower() or "exists" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_register_user_invalid_email(async_client: AsyncClient, clean_db):
    """Test user registration with invalid email format."""
    response = await async_client.post(
        "/users/register",
        json={
            "email": "invalid-email",
            "password": "TestPassword123!",
            "name": "Test User",
        },
    )
    
    assert response.status_code == 422  # Validation error


@pytest.mark.asyncio
async def test_register_user_missing_fields(async_client: AsyncClient, clean_db):
    """Test user registration with missing required fields."""
    # Missing email
    response = await async_client.post(
        "/users/register",
        json={
            "password": "TestPassword123!",
            "name": "Test User",
        },
    )
    assert response.status_code == 422
    
    # Missing password
    response = await async_client.post(
        "/users/register",
        json={
            "email": generate_test_email("user"),
            "name": "Test User",
        },
    )
    assert response.status_code == 422
    
    # Missing name
    response = await async_client.post(
        "/users/register",
        json={
            "email": generate_test_email("user"),
            "password": "TestPassword123!",
        },
    )
    assert response.status_code == 422


# ================== GET /users/me ==================

@pytest.mark.asyncio
async def test_get_user_me_success(authenticated_user_client: AsyncClient, test_user):
    """Test getting current user profile with valid session cookie."""
    user = test_user
    
    response = await authenticated_user_client.get("/users/me")
    
    assert response.status_code == 200
    data = response.json()
    assert_user_response_structure(data)
    assert data["data"]["user_id"] == user["user_id"]
    assert data["data"]["email"] == user["email"]
    assert data["data"]["name"] == user["name"]


@pytest.mark.asyncio
async def test_get_user_me_no_session(async_client: AsyncClient):
    """Test getting user profile without session."""
    response = await async_client.get("/users/me")
    
    assert response.status_code == 401
    assert "not authenticated" in response.json()["detail"].lower() or "authenticated" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_get_user_me_invalid_session(async_client: AsyncClient):
    """Test getting user profile with invalid session."""
    async_client.cookies.set("session_token", "invalid_session_token_12345")
    
    response = await async_client.get("/users/me")
    
    assert response.status_code == 401
    async_client.cookies.clear()


# ================== GET /users/{user_id} ==================

@pytest.mark.asyncio
async def test_get_user_by_id_success(async_client: AsyncClient, test_user):
    """Test getting user by ID (public endpoint)."""
    user = test_user
    
    response = await async_client.get(f"/users/{user['user_id']}")
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == 1
    assert "data" in data
    assert data["data"]["user_id"] == user["user_id"]
    assert data["data"]["name"] == user["name"]
    # Public endpoint should not expose email
    assert "email" not in data["data"]


@pytest.mark.asyncio
async def test_get_user_by_id_not_found(async_client: AsyncClient, clean_db):
    """Test getting non-existent user."""
    response = await async_client.get("/users/999999")
    
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_get_user_by_id_rate_limit(async_client: AsyncClient, test_user):
    """Test that rate limiting works (make multiple requests)."""
    user = test_user
    
    # Make multiple requests (should all succeed, rate limit is 60/minute)
    for _ in range(5):
        response = await async_client.get(f"/users/{user['user_id']}")
        assert response.status_code == 200


# ================== POST /auth/email/user/login ==================

@pytest.mark.asyncio
async def test_user_login_success(async_client: AsyncClient, test_user):
    """Test successful user login."""
    user = test_user
    
    response = await async_client.post(
        "/auth/email/user/login",
        json={
            "email": user["email"],
            "password": user["password"],
        },
    )
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == 1
    assert "message" in data
    assert "data" in data
    assert data["data"]["user_id"] == user["user_id"]
    assert data["data"]["email"] == user["email"]
    
    # Check that session cookie is set
    cookies = response.cookies
    assert "session_token" in cookies
    assert cookies["session_token"] is not None


@pytest.mark.asyncio
async def test_user_login_incorrect_password(async_client: AsyncClient, test_user):
    """Test user login with incorrect password."""
    user = test_user
    
    response = await async_client.post(
        "/auth/email/user/login",
        json={
            "email": user["email"],
            "password": "WrongPassword123!",
        },
    )
    
    assert response.status_code == 401
    assert "incorrect" in response.json()["detail"].lower() or "unauthorized" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_user_login_nonexistent_email(async_client: AsyncClient, clean_db):
    """Test user login with non-existent email."""
    response = await async_client.post(
        "/auth/email/user/login",
        json={
            "email": "nonexistent@example.com",
            "password": "TestPassword123!",
        },
    )
    
    assert response.status_code == 401
    assert "incorrect" in response.json()["detail"].lower() or "unauthorized" in response.json()["detail"].lower()


# ================== POST /auth/logout ==================

@pytest.mark.asyncio
async def test_logout_success(authenticated_user_client: AsyncClient, test_user):
    """Test successful logout."""
    response = await authenticated_user_client.post("/auth/logout")
    
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == 1
    assert "logged out" in data["message"].lower()
    
    # Check that session cookie is cleared
    cookies = response.cookies
    # Cookie should be deleted (empty value or max_age=0)
    if "session_token" in cookies:
        assert cookies["session_token"] == "" or cookies.get("session_token") is None


@pytest.mark.asyncio
async def test_logout_no_session(async_client: AsyncClient):
    """Test logout without session."""
    response = await async_client.post("/auth/logout")
    
    assert response.status_code == 401
    assert "not authenticated" in response.json()["detail"].lower() or "authenticated" in response.json()["detail"].lower()


@pytest.mark.asyncio
async def test_logout_invalidates_session(async_client: AsyncClient, test_user, user_session):
    """Test that logout invalidates the session."""
    from backend.main import app
    
    # Create client with session
    async with AsyncClient(app=app, base_url="http://test") as client:
        client.cookies.set("session_token", user_session)
        
        # Verify session works
        response = await client.get("/users/me")
        assert response.status_code == 200
        
        # Logout
        response = await client.post("/auth/logout")
        assert response.status_code == 200
        
        # Verify session no longer works
        response = await client.get("/users/me")
        assert response.status_code == 401
