"""
Integration tests for user endpoints.

This module contains comprehensive integration tests for user-related
API endpoints including user registration, authentication, and profile management.
"""

import pytest
from fastapi import status
from httpx import AsyncClient

from backend.tests.conftest import assert_user_response_structure, generate_test_email


class TestUserEndpointsIntegration:
    """Integration tests for user endpoints."""

    @pytest.mark.asyncio
    async def test_register_user_and_login_flow(
        self,
        async_client: AsyncClient,
        test_db,
        test_helper,
    ):
        """
        Complete integration test: Create user and then login.

        This test verifies the complete user lifecycle:
        1. Create user with email registration
        2. Verify user exists in database
        3. Login with email/password authentication
        4. Verify session cookie is set
        5. Verify user data consistency
        """
        # Step 1: Create user
        email = generate_test_email("integration")
        password = "TestPassword123!"
        name = "Integration Test User"

        create_response = await async_client.post(
            "/users/register",
            json={
                "email": email,
                "password": password,
                "name": name,
            },
        )

        # Verify user creation response
        assert create_response.status_code == status.HTTP_200_OK
        create_data = create_response.json()
        test_helper.assert_response_structure(create_data, expected_status=1)

        # Verify created user data structure
        user_data = create_data["data"]
        assert_user_response_structure(create_data)

        # Verify user data matches input
        assert user_data["email"] == email
        assert user_data["name"] == name
        assert user_data["is_verified"] is True
        assert "password" not in user_data

        # Step 2: Verify user exists in database
        sql = "SELECT * FROM users WHERE email = $1"
        db_user = await test_db.read_one(sql, email)

        assert db_user is not None
        assert db_user["user_id"] == user_data["user_id"]

        # Step 3: Login with created user
        login_response = await async_client.post(
            "/auth/email/user/login",
            json={
                "email": email,
                "password": password,
            },
        )

        # Verify login response
        assert login_response.status_code == status.HTTP_200_OK
        login_data = login_response.json()
        test_helper.assert_response_structure(login_data, expected_status=1)

        # Step 4: Verify session cookie is set
        cookies = login_response.cookies
        assert "session_token" in cookies
        session_token = cookies["session_token"]
        assert session_token is not None
        assert len(session_token) > 20

        # Step 5: Verify session exists in database
        sql = "SELECT * FROM sessions WHERE user_id = $1"
        db_session = await test_db.read_one(sql, user_data["user_id"])

        assert db_session is not None
        assert db_session["user_id"] == user_data["user_id"]

        print(f"Successfully created user {user_data['user_id']} and authenticated")

    @pytest.mark.asyncio
    async def test_register_user_success(
        self,
        async_client: AsyncClient,
        test_user_data,
        test_helper,
    ):
        """
        Test successful user registration.

        Steps:
        1. Generate unique test email
        2. Send registration request
        3. Verify response structure and data
        """

        response = await async_client.post(
            "/users/register",
            json={
                "email": test_user_data["email"],
                "password": test_user_data["pwd"],
                "name": test_user_data["name"],
            },
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert_user_response_structure(data)
        assert data["data"]["email"] == test_user_data["email"]
        assert data["data"]["name"] == test_user_data["name"]
        assert data["data"]["is_verified"] is True
        assert "password" not in data["data"]

    @pytest.mark.asyncio
    async def test_register_user_with_optional_fields(
        self,
        async_client: AsyncClient,
        test_db,
        test_helper,
    ):
        """
        Test user registration with optional fields.

        Steps:
        1. Generate unique test email
        2. Send registration request with phone and address
        3. Verify optional fields are stored correctly
        """
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

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert_user_response_structure(data)
        assert data["data"]["phone"] == "+1234567890"
        assert data["data"]["address"] == "123 Test St, Test City"

    @pytest.mark.asyncio
    async def test_register_user_duplicate_email_fails(self, async_client: AsyncClient, test_user_data):
        """
        Test that user registration fails with duplicate email.

        Steps:
        1. Create a user with test email
        2. Attempt to register with same email
        3. Verify 400 Bad Request response
        """

        # Attempt to create user with same email
        response = await async_client.post(
            "/users/register",
            json={
                "email": test_user_data["email"],
                "password": test_user_data["pwd"],
                "name": test_user_data["name"],
            },
        )

        # Should fail with 400 Bad Request
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = response.json()
        assert "already" in error_data["detail"].lower() or "exists" in error_data["detail"].lower()

    @pytest.mark.asyncio
    async def test_register_user_with_invalid_email_fails(
        self,
        async_client: AsyncClient,
        test_db,
    ):
        """
        Test that user registration fails with invalid email format.
        """
        response = await async_client.post(
            "/users/register",
            json={
                "email": "invalid-email",
                "password": "TestPassword123!",
                "name": "Test User",
            },
        )

        # Should fail with 422 Validation Error
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_register_user_missing_fields_fails(
        self,
        async_client: AsyncClient,
        test_db,
    ):
        """
        Test that user registration fails with missing required fields.

        Steps:
        1. Test missing email
        2. Test missing password
        3. Test missing name
        """
        # Missing email
        response = await async_client.post(
            "/users/register",
            json={
                "password": "TestPassword123!",
                "name": "Test User",
            },
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Missing password
        response = await async_client.post(
            "/users/register",
            json={
                "email": generate_test_email("user"),
                "name": "Test User",
            },
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

        # Missing name
        response = await async_client.post(
            "/users/register",
            json={
                "email": generate_test_email("user"),
                "password": "TestPassword123!",
            },
        )
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_get_user_me_without_session_fails(self, async_client: AsyncClient):
        """
        Test that getting user profile fails without session.
        """
        response = await async_client.get("/users/me")

        # Should fail with 401 Unauthorized
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        error_data = response.json()
        assert "not authenticated" in error_data["detail"].lower() or "authenticated" in error_data["detail"].lower()

    @pytest.mark.asyncio
    async def test_get_user_me_with_invalid_session_fails(self, async_client: AsyncClient):
        """
        Test that getting user profile fails with invalid session.
        """
        async_client.cookies.set("session_token", "invalid_session_token_12345")

        response = await async_client.get("/users/me")

        # Should fail with 401 Unauthorized
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        async_client.cookies.clear()

    @pytest.mark.asyncio
    async def test_get_user_by_id_not_found(self, async_client: AsyncClient, test_db):
        """
        Test getting non-existent user returns 404.
        """
        response = await async_client.get("/users/999999")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_login_with_incorrect_password_fails(
        self,
        async_client: AsyncClient,
        test_user_data,
    ):
        """
        Test that login fails with incorrect password.
        """
        response = await async_client.post(
            "/auth/email/user/login",
            json={
                "email": test_user_data["email"],
                "password": "WrongPassword123!",
            },
        )

        # Should fail with 401 Unauthorized
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        error_data = response.json()
        assert "incorrect" in error_data["detail"].lower() or "unauthorized" in error_data["detail"].lower()

    @pytest.mark.asyncio
    async def test_login_with_nonexistent_email_fails(
        self,
        async_client: AsyncClient,
        test_db,
    ):
        """
        Test that login fails with non-existent email.
        """
        response = await async_client.post(
            "/auth/email/user/login",
            json={
                "email": "nonexistent@example.com",
                "password": "TestPassword123!",
            },
        )

        # Should fail with 401 Unauthorized
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        error_data = response.json()
        assert "incorrect" in error_data["detail"].lower() or "unauthorized" in error_data["detail"].lower()

    @pytest.mark.asyncio
    async def test_logout_success(
        self,
        async_client: AsyncClient,
        test_user_data,
        test_helper,
    ):
        """
        Test successful logout.

        Steps:
        1. login with test user data
        2. Set session cookie from login response
        3. Send logout request
        4. Verify response
        5. Verify session cookie is cleared
        """

        response = await async_client.post(
            "/auth/email/user/login",
            json={
                "email": test_user_data["email"],
                "password": test_user_data["pwd"],
            },
        )

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert "login successful" in data["message"].lower()

        # Extract and set the session cookie for subsequent requests
        session_token = response.cookies.get("session_token")
        assert session_token is not None
        async_client.cookies.set("session_token", session_token)

        response = await async_client.post("/auth/logout")

        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert "logged out" in data["message"].lower()

        # Check that session cookie is cleared
        cookies = response.cookies
        # Cookie should be deleted (empty value or max_age=0)
        if "session_token" in cookies:
            assert cookies["session_token"] == "" or cookies.get("session_token") is None

        # Clear cookies from client for test isolation
        async_client.cookies.clear()

    @pytest.mark.asyncio
    async def test_logout_without_session_fails(self, async_client: AsyncClient):
        """
        Test that logout fails without session.
        """
        response = await async_client.post("/auth/logout")

        # Should fail with 401 Unauthorized
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        error_data = response.json()
        assert "not authenticated" in error_data["detail"].lower() or "authenticated" in error_data["detail"].lower()
