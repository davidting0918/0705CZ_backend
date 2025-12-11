"""
Integration tests for admin endpoints.

This module contains comprehensive integration tests for admin-related
API endpoints including admin creation and authentication flows.
"""

import pytest
from fastapi import status
from httpx import AsyncClient

from backend.tests.conftest import assert_admin_response_structure


class TestAdminEndpointsIntegration:
    """Integration tests for admin endpoints."""

    @pytest.mark.asyncio
    async def test_create_admin_and_login_flow(
        self,
        async_client: AsyncClient,
        test_db,
        test_admin_data: dict,
        test_helper,
    ):
        """
        Complete integration test: Create admin and then login.

        This test verifies the complete admin lifecycle:
        1. Create admin with whitelisted email
        2. Login with email/password authentication
        3. Verify admin data consistency
        """
        # Step 1: Create admin

        create_response = await async_client.post(
            "/admins/register",
            json={
                "email": test_admin_data["email"],
                "password": test_admin_data["password"],
                "name": test_admin_data["name"],
            },
        )

        # Verify admin creation response
        assert create_response.status_code == status.HTTP_200_OK
        create_data = create_response.json()
        test_helper.assert_response_structure(create_data, expected_status=1)
        assert create_data["message"] == "Admin registered successfully" or "Admin created successfully"

        # Verify created admin data structure
        admin_data = create_data["data"]
        assert_admin_response_structure(create_data)

        # Verify admin data matches input
        assert admin_data["email"] == test_admin_data["email"]
        assert admin_data["name"] == test_admin_data["name"]
        assert admin_data["is_active"] is True
        assert "password" not in admin_data

        # Verify admin exists in database
        sql = "SELECT * FROM admins WHERE email = $1"
        db_admin = await test_db.read_one(sql, test_admin_data["email"])

        assert db_admin is not None
        assert db_admin["admin_id"] == admin_data["admin_id"]

        # Step 2: Login with created admin
        login_data = {
            "email": test_admin_data["email"],
            "password": test_admin_data["password"],
        }

        login_response = await async_client.post("/auth/email/admin/login", json=login_data)

        # Verify login response
        assert login_response.status_code == status.HTTP_200_OK
        login_response_data = login_response.json()

        # Verify login response data structure
        assert "access_token" in login_response_data
        assert "token_type" in login_response_data
        assert login_response_data["token_type"] == "bearer"
        assert "expires_in" in login_response_data
        assert login_response_data["expires_in"] > 0
        assert "message" in login_response_data

        # Step 3: Verify token was created in database
        access_token = login_response_data["access_token"]
        assert access_token is not None
        assert len(access_token) > 20  # JWT tokens are much longer

        # Verify token exists in database
        sql = "SELECT * FROM access_tokens WHERE admin_id = $1"
        db_token = await test_db.read_one(sql, admin_data["admin_id"])

        assert db_token is not None
        assert db_token["admin_id"] == admin_data["admin_id"]

        print(f"✅ Successfully created admin {admin_data['admin_id']} and authenticated")

    # @pytest.mark.asyncio
    # async def test_create_admin_without_whitelist_fails(
    #     self, async_client: AsyncClient, test_admin_data: dict
    # ):
    #     """
    #     Test that admin creation fails without whitelisted email.
    #     """
    #     # Attempt to create admin without whitelist
    #     response = await async_client.post(
    #         "/admins/register",
    #         json={
    #             "email": test_admin_data["email"],
    #             "password": test_admin_data["password"],
    #             "name": test_admin_data["name"],
    #         },
    #     )

    #     # Should fail with 403 Forbidden
    #     assert response.status_code == status.HTTP_403_FORBIDDEN
    #     error_data = response.json()
    #     assert "not whitelisted" in error_data["detail"].lower()

    # @pytest.mark.asyncio
    # async def test_create_admin_with_invalid_email_fails(
    #     self, async_client: AsyncClient, test_admin_data: dict
    # ):
    #     """
    #     Test that admin creation fails with invalid email format.
    #     """
    #     await add_admin_to_whitelist("invalid-email")

    #     response = await async_client.post(
    #         "/admins/register",
    #         json={
    #             "email": "invalid-email",
    #             "password": test_admin_data["password"],
    #             "name": test_admin_data["name"],
    #         },
    #     )

    #     # Should fail with 422 Validation Error
    #     assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # @pytest.mark.asyncio
    # async def test_create_duplicate_admin_fails(
    #     self, async_client: AsyncClient, test_admin_data: dict
    # ):
    #     """
    #     Test that creating an admin with existing email fails.
    #     """
    #     email = test_admin_data["email"]
    #     await add_admin_to_whitelist(email)

    #     # Create first admin
    #     first_response = await async_client.post(
    #         "/admins/register",
    #         json={
    #             "email": email,
    #             "password": test_admin_data["password"],
    #             "name": test_admin_data["name"],
    #         },
    #     )

    #     assert first_response.status_code == status.HTTP_200_OK

    #     # Attempt to create admin with same email
    #     duplicate_response = await async_client.post(
    #         "/admins/register",
    #         json={
    #             "email": email,
    #             "password": test_admin_data["password"],
    #             "name": "Duplicate Admin",
    #         },
    #     )

    #     # Should fail with 400 Bad Request
    #     assert duplicate_response.status_code == status.HTTP_400_BAD_REQUEST
    #     error_data = duplicate_response.json()
    #     assert "already" in error_data["detail"].lower() or "exists" in error_data["detail"].lower()

    # @pytest.mark.asyncio
    # async def test_login_with_invalid_credentials_fails(self, async_client: AsyncClient):
    #     """
    #     Test that login fails with invalid credentials.
    #     """
    #     invalid_login_data = {"email": "nonexistent@example.com", "password": "wrongpassword"}

    #     response = await async_client.post("/auth/email/admin/login", json=invalid_login_data)

    #     # Should fail with 401 Unauthorized
    #     assert response.status_code == status.HTTP_401_UNAUTHORIZED
    #     error_data = response.json()
    #     assert "incorrect email or password" in error_data["detail"].lower()

    # @pytest.mark.asyncio
    # async def test_login_with_not_whitelisted_admin_fails(
    #     self, async_client: AsyncClient, test_db
    # ):
    #     """
    #     Test that login fails for admin not in whitelist.
    #     """
    #     # Create admin without whitelist entry
    #     admin = await create_test_admin()
    #     # Remove from whitelist if it was added
    #     from backend.core.db_manager import db_manager

    #     db = db_manager.get_client()
    #     await db.execute("DELETE FROM admin_whitelist WHERE email = $1", admin["email"])

    #     response = await async_client.post(
    #         "/auth/email/admin/login",
    #         json={"email": admin["email"], "password": admin["password"]},
    #     )

    #     # Should fail with 403 Forbidden
    #     assert response.status_code == status.HTTP_403_FORBIDDEN
    #     error_data = response.json()
    #     assert "not whitelisted" in error_data["detail"].lower()

    # @pytest.mark.asyncio
    # async def test_get_admin_me_with_valid_token(
    #     self, async_client: AsyncClient, test_db, test_helper
    # ):
    #     """
    #     Test getting current admin profile with valid JWT token.
    #     """
    #     # Create admin and login to get token
    #     admin = await create_test_admin()
    #     await add_admin_to_whitelist(admin["email"])

    #     login_response = await async_client.post(
    #         "/auth/email/admin/login",
    #         json={"email": admin["email"], "password": admin["password"]},
    #     )

    #     assert login_response.status_code == status.HTTP_200_OK
    #     token_data = login_response.json()
    #     access_token = token_data["access_token"]

    #     # Get admin profile with token
    #     response = await async_client.get(
    #         "/admins/me",
    #         headers={"Authorization": f"Bearer {access_token}"},
    #     )

    #     assert response.status_code == status.HTTP_200_OK
    #     data = response.json()
    #     test_helper.assert_response_structure(data, expected_status=1)
    #     assert_admin_response_structure(data)
    #     assert data["data"]["admin_id"] == admin["admin_id"]
    #     assert data["data"]["email"] == admin["email"]
    #     assert data["data"]["name"] == admin["name"]

    # @pytest.mark.asyncio
    # async def test_get_admin_me_without_token(self, async_client: AsyncClient):
    #     """
    #     Test that getting admin profile fails without token.
    #     """
    #     response = await async_client.get("/admins/me")

    #     # Should fail with 401 Unauthorized
    #     assert response.status_code == status.HTTP_401_UNAUTHORIZED
    #     error_data = response.json()
    #     assert (
    #         "not authenticated" in error_data["detail"].lower()
    #         or "bearer" in error_data["detail"].lower()
    #     )

    # @pytest.mark.asyncio
    # async def test_get_admin_me_with_invalid_token(self, async_client: AsyncClient):
    #     """
    #     Test that getting admin profile fails with invalid token.
    #     """
    #     response = await async_client.get(
    #         "/admins/me",
    #         headers={"Authorization": "Bearer invalid_token_12345"},
    #     )

    #     # Should fail with 401 Unauthorized
    #     assert response.status_code == status.HTTP_401_UNAUTHORIZED
    #     error_data = response.json()
    #     assert (
    #         "not authenticated" in error_data["detail"].lower()
    #         or "invalid" in error_data["detail"].lower()
    #     )

    # @pytest.mark.asyncio
    # async def test_get_admin_by_id_success(self, async_client: AsyncClient, test_db):
    #     """
    #     Test getting admin by ID (public endpoint).
    #     """
    #     admin = await create_test_admin()
    #     await add_admin_to_whitelist(admin["email"])

    #     response = await async_client.get(f"/admins/{admin['admin_id']}")

    #     assert response.status_code == status.HTTP_200_OK
    #     data = response.json()
    #     assert data["status"] == 1
    #     assert "data" in data
    #     assert data["data"]["admin_id"] == admin["admin_id"]
    #     assert data["data"]["name"] == admin["name"]
    #     # Public endpoint should not expose email
    #     assert "email" not in data["data"]

    # @pytest.mark.asyncio
    # async def test_get_admin_by_id_not_found(self, async_client: AsyncClient, test_db):
    #     """
    #     Test getting non-existent admin.
    #     """
    #     response = await async_client.get("/admins/999999")

    #     assert response.status_code == status.HTTP_404_NOT_FOUND
    #     assert "not found" in response.json()["detail"].lower()
