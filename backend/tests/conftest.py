"""
Test configuration and fixtures for PetCare API tests.

This module provides shared test fixtures, database setup/teardown,
and common test utilities used across all test modules.
"""

import asyncio
import os
import random
import string
import uuid
from datetime import datetime as dt
from datetime import timezone as tz
from typing import AsyncGenerator, Dict

import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

# Set test environment before importing application modules
os.environ["PYTEST_RUNNING"] = "1"
os.environ["APP_ENV"] = "test"

from backend.core.db_manager import close_database, get_db, init_database
from backend.core.security import (
    generate_admin_id,
    generate_user_id,
    hash_password_admin,
    hash_password_user,
)
from backend.main import app

tables = [
    "users",
    "products",
    "orders",
    "order_details",
    "carts",
    "cart_items",
    "sessions",
    "admins",
    "access_tokens",
    "admin_whitelist",
]


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def test_db():
    """
    Provide test database instance with automatic cleanup.

    This fixture creates a test database connection and ensures
    all test tables are cleaned up after the test session.
    """
    # Initialize test database
    await init_database(environment="test")

    # clean up table before test
    test_db = get_db()
    try:
        for table in tables:
            await test_db.execute(f"DELETE FROM {table}")
    except Exception as e:
        print(f"Warning: Error cleaning up table {table}: {e}")

    yield test_db

    try:
        for table in tables:
            await test_db.execute(f"DELETE FROM {table}")
    except Exception as e:
        print(f"Warning: Error cleaning up table {table}: {e}")

    await close_database()


# ================== CLEANUP SYSTEM 1: PER-TEST CLEANING ==================


@pytest_asyncio.fixture
async def clean_db_per_test(test_db):
    """
    SYSTEM 1: Clean database between EACH test function.

    Use this fixture explicitly in test classes that need full isolation:
    - Preserves session-scoped users and API keys
    - Cleans test-specific data (groups, pets, tokens) between each test
    - Provides maximum test isolation but slower performance

    Usage: Add as dependency to test class or individual tests
    """
    # Tables to clean BETWEEN tests (preserve session data)
    test_data_tables = [
        "products",
        "orders",
        "order_details",
        "carts",
        "cart_items",
    ]

    # Clean test data before test
    for table in test_data_tables:
        try:
            await test_db.execute(f"DELETE FROM {table}")
        except Exception as e:
            print(f"Warning: Error cleaning table {table}: {e}")

    yield

    # Clean test data after test (same as before)
    for table in test_data_tables:
        try:
            await test_db.execute(f"DELETE FROM {table}")
        except Exception as e:
            print(f"Warning: Error cleaning table {table}: {e}")


@pytest_asyncio.fixture(autouse=True)
async def auto_clean_per_test(request, test_db):
    """
    Auto-apply per-test cleaning for test classes marked with @pytest.mark.clean_per_test

    Usage:
    @pytest.mark.clean_per_test
    class TestSomeFeature:
        # Tests here will auto-clean between each test
    """
    # Check if the test is marked for per-test cleaning
    if request.node.get_closest_marker("clean_per_test"):
        # Apply the same logic as clean_db_per_test
        test_data_tables = [
            "products",
            "orders",
            "order_details",
            "carts",
            "cart_items",
        ]

        # Clean test data before test
        for table in test_data_tables:
            try:
                await test_db.execute(f"DELETE FROM {table}")
            except Exception as e:
                print(f"Warning: Error cleaning table {table}: {e}")

        yield

        # Clean test data after test
        for table in test_data_tables:
            try:
                await test_db.execute(f"DELETE FROM {table}")
            except Exception as e:
                print(f"Warning: Error cleaning table {table}: {e}")
    else:
        # Just yield without cleaning
        yield


# ================== CLEANUP SYSTEM 2: SESSION-ONLY CLEANING ==================


@pytest_asyncio.fixture(scope="session")
async def clean_db_session_only():
    """
    SYSTEM 2: Clean database ONLY at session start and end.

    Use this for test classes that want to preserve data across tests:
    - Data persists between individual tests within the session
    - Only cleans at the very beginning and end of the test session
    - Faster performance but less test isolation
    - Good for integration tests or related test sequences

    Usage: This runs automatically at session scope
    """
    # Initialize database and clean at session start
    await init_database(environment="test")
    db = get_db()

    session_tables = [
        "products",
        "orders",
        "order_details",
        "carts",
        "cart_items",
    ]

    print("🧹 SESSION START: Cleaning test data tables...")
    for table in session_tables:
        try:
            await db.execute(f"DELETE FROM {table}")
            print(f"  ✅ Cleaned {table}")
        except Exception as e:
            print(f"  ⚠️  Error cleaning {table}: {e}")

    yield

    # Clean at session end
    print("🧹 SESSION END: Cleaning test data tables...")
    for table in session_tables:
        try:
            await db.execute(f"DELETE FROM {table}")
            print(f"  ✅ Final cleanup {table}")
        except Exception as e:
            print(f"  ⚠️  Error in final cleanup {table}: {e}")


@pytest_asyncio.fixture(scope="session", autouse=True)
async def cleanup_session_data():
    """
    Clean up ALL data after the entire test session.
    This ensures a completely clean state for the next test run.
    Note: This cleans user/auth data, while clean_db_session_only handles test data.
    """
    yield  # Let all tests run first

    # After all tests complete, clean everything including user data
    await init_database(environment="test")
    db = get_db()

    print("🧹 Performing final session cleanup...")
    for table in tables:
        try:
            result = await db.execute(f"DELETE FROM {table}")
            print(f"  ✅ Cleaned {table}: {result}")
        except Exception as e:
            print(f"  ⚠️  Error cleaning {table}: {e}")


# ================== USAGE EXAMPLES AND HELPERS ==================

"""
USAGE EXAMPLES:

1. FOR TESTS THAT NEED FULL ISOLATION (each test starts fresh):

   Method A - Using marker:
   @pytest.mark.clean_per_test
   class TestIsolatedFeature:
       def test_something(self, async_client):
           # This test starts with clean DB
           pass

   Method B - Using explicit fixture:
   class TestIsolatedFeature:
       def test_something(self, async_client, clean_db_per_test):
           # This test starts with clean DB
           pass

2. FOR TESTS THAT SHARE DATA ACROSS THE SESSION (faster, data persists):

   class TestIntegratedFeature:  # No marker, uses session-only cleaning
       def test_step1(self, async_client):
           # Create some data
           pass

       def test_step2(self, async_client):
           # Data from test_step1 still exists
           pass

3. MIXED APPROACH:
   - Mark specific test classes that need isolation
   - Leave others unmarked for session-only cleaning
"""


@pytest_asyncio.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """
    Provide async HTTP client for testing API endpoints.

    This fixture creates an AsyncClient instance configured
    to work with the FastAPI test application.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        yield client


@pytest.fixture
def sync_client() -> TestClient:
    """
    Provide synchronous HTTP client for simple tests.

    Use this for basic endpoint tests that don't require
    complex async operations.
    """
    return TestClient(app)


@pytest_asyncio.fixture
async def test_user_data() -> Dict[str, str]:
    """
    Provide test user data for user creation tests.

    Returns:
        Dict containing user registration information
    """
    return {
        "email": f"test_{str(uuid.uuid4())[:8]}@example.com",
        "name": f"Test User {str(uuid.uuid4())[:8]}",
        "pwd": f"TestPassword{str(uuid.uuid4())[:8]}",
    }


@pytest_asyncio.fixture(scope="session")
async def test_admin_data() -> Dict[str, str]:
    """
    Provide test admin data for admin creation tests.

    Returns:
        Dict containing admin registration information
    """
    return {
        "email": f"admin{str(uuid.uuid4())[:8]}@example.com",
        "name": f"Test Admin {str(uuid.uuid4())[:8]}",
        "password": f"TestPassword{str(uuid.uuid4())[:8]}",
    }

@pytest_asyncio.fixture
async def new_admin_data() -> Dict[str, str]:
    return {
        "email": f"test_{str(uuid.uuid4())[:8]}@example.com",
        "name": f"Test Admin {str(uuid.uuid4())[:8]}",
        "pwd": f"TestPassword{str(uuid.uuid4())[:8]}",
    }

# Test utilities
class TestHelper:
    """Helper class containing common test utilities."""

    @staticmethod
    def assert_response_structure(response_data: dict, expected_status: int = 1):
        """
        Assert that response follows expected API structure.

        Args:
            response_data: Response JSON data
            expected_status: Expected status code (default: 1 for success)
        """
        assert "status" in response_data
        assert "message" in response_data
        assert response_data["status"] == expected_status

        if expected_status == 1:
            assert "data" in response_data

    @staticmethod
    def assert_user_structure(user_data: dict):
        """
        Assert that user data contains required fields.

        Args:
            user_data: User data dictionary
        """
        required_fields = [
            "id",
            "email",
            "name",
            "created_at",
            "updated_at",
            "is_active"
        ]
        for field in required_fields:
            assert field in user_data, f"Missing required field: {field}"

@pytest.fixture
def test_helper() -> TestHelper:
    """Provide test helper instance."""
    return TestHelper()


# ================== TEST UTILITY FUNCTIONS ==================


def generate_test_email(prefix: str = "test") -> str:
    """Generate a unique test email address."""
    random_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{prefix}_{random_suffix}@example.com"


def generate_test_password() -> str:
    """Generate a test password."""
    return "TestPassword123!"


def assert_admin_response_structure(response_data: dict) -> None:
    """Assert that admin response has correct structure."""
    assert "status" in response_data
    assert "message" in response_data
    assert "data" in response_data
    assert response_data["status"] == 1
    
    data = response_data["data"]
    assert "admin_id" in data
    assert "email" in data
    assert "name" in data
    assert "is_active" in data
    assert "created_at" in data
    assert "updated_at" in data


def assert_user_response_structure(response_data: dict) -> None:
    """Assert that user response has correct structure."""
    assert "status" in response_data
    assert "message" in response_data
    assert "data" in response_data
    assert response_data["status"] == 1
    
    data = response_data["data"]
    assert "user_id" in data
    assert "email" in data
    assert "name" in data
    assert "is_active" in data
    assert "is_verified" in data
    assert "created_at" in data
    assert "updated_at" in data


# ================== HELPER FUNCTIONS ==================


async def add_admin_to_whitelist(email: str) -> None:
    """
    Add an email to the admin whitelist.
    
    Args:
        email: Email address to add to whitelist
    """
    db = get_db()
    try:
        await db.execute(
            "INSERT INTO admin_whitelist (email) VALUES ($1) ON CONFLICT (email) DO NOTHING",
            email,
        )
    except Exception as e:
        print(f"Warning: Error adding {email} to whitelist: {e}")

# ================== SESSION-SCOPED TEST USERS (PERFORMANCE OPTIMIZED) ==================


@pytest_asyncio.fixture(scope="session")
async def session_admins(test_db) -> Dict[str, Dict[str, str]]:
    """
    Create session-wide test admins that persist across all tests.
    This dramatically improves test performance by avoiding repeated admin creation.

    Returns:
        Dict with 'admin1' key containing admin info and access token
    """
    from httpx import AsyncClient

    admin_configs = [
        {"email": "session.admin1@example.com", "name": "Session Admin 1", "password": "TestPassword123!", "key": "admin1"},
    ]

    created_admins = {}

    # Add admins to whitelist first
    for admin_config in admin_configs:
        await add_admin_to_whitelist(admin_config["email"])

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://testserver") as client:
        for admin_config in admin_configs:
            print(f"Creating session admin: {admin_config['email']}")

            # Try to create admin
            response = await client.post(
                "/admins/register",
                headers={
                    "Content-Type": "application/json",
                },
                json={"email": admin_config["email"], "name": admin_config["name"], "password": admin_config["password"]},
            )

            admin_created = False
            # Handle admin creation response
            if response.status_code == 200:
                # Admin created successfully
                created_admin = response.json()["data"]
                admin_created = True
                admin_info = created_admin
                print(f"✅ Session admin created: {admin_config['name']} (ID: {created_admin['admin_id']})")
            elif response.status_code == 400 and "already exists" in response.text.lower():
                # Admin already exists from previous test run - fetch it
                from backend.admins.admin_services import admin_service
                existing_admin = await admin_service.get_admin_by_email(admin_config["email"])
                if existing_admin:
                    admin_info = existing_admin
                    print(f"⚠️  Admin already exists, will use existing admin: {admin_config['email']}")
                else:
                    error_msg = f"Admin already exists but could not fetch: {admin_config['email']}"
                    print(f"❌ {error_msg}")
                    raise Exception(error_msg)
            else:
                # Other error - fail fast
                error_msg = f"Failed to create session admin {admin_config['name']}: {response.text}"
                print(f"❌ {error_msg}")
                raise Exception(error_msg)

            # Login to get JWT token (works for both new and existing admins)
            login_response = await client.post(
                "/auth/email/admin/login", json={"email": admin_config["email"], "password": admin_config["password"]}
            )

            if login_response.status_code != 200:
                error_msg = f"Failed to login session admin {admin_config['name']}: {login_response.text}"
                print(f"❌ {error_msg}")
                raise Exception(error_msg)

            token_data = login_response.json()
            access_token = token_data["access_token"]

            # Get admin info if not already available
            if not admin_created:
                # For existing admins, fetch user info using the token
                me_response = await client.get(
                    "/admins/me",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "Content-Type": "application/json",
                    },
                )
                if me_response.status_code != 200:
                    error_msg = f"Failed to get admin info for {admin_config['name']}: {me_response.text}"
                    print(f"❌ {error_msg}")
                    raise Exception(error_msg)
                admin_info = me_response.json()["data"]
                print(f"✅ Session admin ready (existing): {admin_config['name']} (ID: {admin_info['admin_id']})")

            created_admins[admin_config["key"]] = {
                "admin_id": admin_info["admin_id"],
                "email": admin_config["email"],
                "name": admin_config["name"],
                "password": admin_config["password"],
                "access_token": access_token,
            }

    yield created_admins

    # Cleanup after all tests (optional - database cleanup handles this)
    print("🧹 Session admins will be cleaned up by database cleanup")


@pytest_asyncio.fixture(scope="session")
async def session_admin1(session_admins: Dict[str, Dict[str, str]]) -> Dict[str, str]:
    """Get session admin 1 info"""
    return session_admins["admin1"]


@pytest_asyncio.fixture(scope="session")
async def session_auth_headers_admin1(session_admin1: Dict[str, str]) -> Dict[str, str]:
    """Get auth headers for session admin 1"""
    return {"Authorization": f"Bearer {session_admin1['access_token']}", "Content-Type": "application/json"}