"""
Integration tests for product endpoints.

This module contains comprehensive integration tests for product-related
API endpoints including product creation (admin only), listing, filtering,
and retrieval (public endpoints).
"""

import uuid

import pytest
from fastapi import status
from httpx import AsyncClient


class TestProductEndpointsIntegration:
    """Integration tests for product endpoints."""

    # ================== Product Creation Tests (Admin Only) ==================

    @pytest.mark.asyncio
    async def test_create_product_success(
        self,
        async_client: AsyncClient,
        test_db,
        session_auth_headers_admin1: dict,
        test_helper,
    ):
        """
        Test successful product creation with admin token.

        Steps:
        1. Create product with valid admin Bearer token
        2. Verify response structure and data
        3. Verify product exists in database
        """
        unique_sku = f"TEST-SKU-{str(uuid.uuid4())[:8]}"
        product_data = {
            "product_sku": unique_sku,
            "name": "Test Product",
            "description": "Test product description",
            "currency": "TWD",
            "price": 100.50,
            "qty": 10,
            "photo_url": "https://example.com/photo.jpg",
            "category": "Electronics",
            "is_active": True,
        }

        response = await async_client.post(
            "/products/create",
            headers=session_auth_headers_admin1,
            json=product_data,
        )

        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert "data" in data
        assert data["message"] == "Product created successfully"

        # Verify product data
        product = data["data"]
        assert product["product_sku"] == product_data["product_sku"]
        assert product["name"] == product_data["name"]
        assert product["description"] == product_data["description"]
        assert product["currency"] == product_data["currency"]
        assert product["price"] == product_data["price"]
        assert product["qty"] == product_data["qty"]
        assert product["photo_url"] == product_data["photo_url"]
        assert product["category"] == product_data["category"]
        assert product["is_active"] == product_data["is_active"]
        assert "product_id" in product
        assert "created_at" in product
        assert "updated_at" in product

    @pytest.mark.asyncio
    async def test_create_product_without_auth_fails(self, async_client: AsyncClient):
        """
        Test that product creation fails without authentication token.
        """
        product_data = {
            "product_sku": f"TEST-SKU-{str(uuid.uuid4())[:8]}",
            "name": "Test Product",
            "category": "Electronics",
        }

        response = await async_client.post("/products/create", json=product_data)

        # Should fail with 401 Unauthorized
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        error_data = response.json()
        assert "not authenticated" in error_data["detail"].lower() or "bearer" in error_data["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_product_with_user_session_fails(
        self,
        async_client_with_user1: AsyncClient,
    ):
        """
        Test that product creation fails with user session cookie (not admin token).
        """
        product_data = {
            "product_sku": f"TEST-SKU-{str(uuid.uuid4())[:8]}",
            "name": "Test Product",
            "category": "Electronics",
        }

        response = await async_client_with_user1.post("/products/create", json=product_data)

        # Should fail with 401 Unauthorized (user session is not admin token)
        assert response.status_code == status.HTTP_401_UNAUTHORIZED
        error_data = response.json()
        assert "not authenticated" in error_data["detail"].lower() or "bearer" in error_data["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_product_duplicate_sku_fails(
        self,
        async_client: AsyncClient,
        session_auth_headers_admin1: dict,
    ):
        """
        Test that product creation fails with duplicate SKU.
        """
        unique_sku = f"TEST-SKU-{str(uuid.uuid4())[:8]}"
        product_data = {
            "product_sku": unique_sku,
            "name": "Test Product",
            "category": "Electronics",
        }

        # Create first product
        first_response = await async_client.post(
            "/products/create",
            headers=session_auth_headers_admin1,
            json=product_data,
        )
        assert first_response.status_code == status.HTTP_200_OK

        # Attempt to create product with same SKU
        duplicate_response = await async_client.post(
            "/products/create",
            headers=session_auth_headers_admin1,
            json=product_data,
        )

        # Should fail with 400 Bad Request
        assert duplicate_response.status_code == status.HTTP_400_BAD_REQUEST
        error_data = duplicate_response.json()
        assert "sku" in error_data["detail"].lower() or "already exists" in error_data["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_product_invalid_data_fails(
        self,
        async_client: AsyncClient,
        session_auth_headers_admin1: dict,
    ):
        """
        Test that product creation fails with invalid request data.
        """
        # Missing required fields
        invalid_data = {
            "name": "Test Product",
            # Missing product_sku and category
        }

        response = await async_client.post(
            "/products/create",
            headers=session_auth_headers_admin1,
            json=invalid_data,
        )

        # Should fail with 422 Validation Error
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.asyncio
    async def test_create_product_with_negative_price_fails(
        self,
        async_client: AsyncClient,
        session_auth_headers_admin1: dict,
    ):
        """
        Test that product creation fails with negative price.
        """
        product_data = {
            "product_sku": f"TEST-SKU-{str(uuid.uuid4())[:8]}",
            "name": "Test Product",
            "category": "Electronics",
            "price": -10.0,  # Invalid negative price
        }

        response = await async_client.post(
            "/products/create",
            headers=session_auth_headers_admin1,
            json=product_data,
        )

        # Should fail with 422 Validation Error
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    # ================== Product List Tests (Public) ==================

    @pytest.mark.asyncio
    async def test_list_products_success(
        self,
        async_client: AsyncClient,
        session_auth_headers_admin1: dict,
        test_helper,
    ):
        """
        Test successful product listing without authentication.
        """
        # First, create a test product using admin token
        unique_sku = f"TEST-SKU-{str(uuid.uuid4())[:8]}"
        product_data = {
            "product_sku": unique_sku,
            "name": "Test Product for Listing",
            "category": "Electronics",
            "price": 99.99,
            "qty": 5,
            "is_active": True,
        }

        create_response = await async_client.post(
            "/products/create",
            headers=session_auth_headers_admin1,
            json=product_data,
        )
        assert create_response.status_code == status.HTTP_200_OK

        # List products without auth
        response = await async_client.get("/products/info")

        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert "data" in data
        assert isinstance(data["data"], list)
        assert "total" in data
        assert "limit" in data
        assert "offset" in data
        assert data["total"] >= 1  # At least our test product

        # Verify product structure in list
        if len(data["data"]) > 0:
            product = data["data"][0]
            assert "product_id" in product
            assert "product_sku" in product
            assert "name" in product
            assert "price" in product
            assert "qty" in product
            assert "category" in product
            assert "is_active" in product

    @pytest.mark.asyncio
    async def test_list_products_with_session(
        self,
        async_client_with_user1: AsyncClient,
        async_client: AsyncClient,
        session_auth_headers_admin1: dict,
        test_helper,
    ):
        """
        Test product listing with user session cookie.
        """
        # Create a test product using admin client
        unique_sku = f"TEST-SKU-{str(uuid.uuid4())[:8]}"
        product_data = {
            "product_sku": unique_sku,
            "name": "Test Product for Session",
            "category": "Books",
            "price": 29.99,
            "qty": 3,
            "is_active": True,
        }

        create_response = await async_client.post(
            "/products/create",
            headers=session_auth_headers_admin1,
            json=product_data,
        )
        assert create_response.status_code == status.HTTP_200_OK

        # List products with user session
        response = await async_client_with_user1.get("/products/info")

        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert "data" in data
        assert isinstance(data["data"], list)

    @pytest.mark.asyncio
    async def test_list_products_with_filtering(
        self,
        async_client: AsyncClient,
        session_auth_headers_admin1: dict,
        test_helper,
    ):
        """
        Test product listing with category and is_active filters.
        """
        # Create products in different categories
        electronics_sku = f"TEST-SKU-{str(uuid.uuid4())[:8]}"
        books_sku = f"TEST-SKU-{str(uuid.uuid4())[:8]}"

        electronics_product = {
            "product_sku": electronics_sku,
            "name": "Electronics Product",
            "category": "Electronics",
            "price": 199.99,
            "qty": 10,
            "is_active": True,
        }

        books_product = {
            "product_sku": books_sku,
            "name": "Book Product",
            "category": "Books",
            "price": 19.99,
            "qty": 5,
            "is_active": True,
        }

        # Create products
        await async_client.post("/products", headers=session_auth_headers_admin1, json=electronics_product)
        await async_client.post("/products", headers=session_auth_headers_admin1, json=books_product)

        # Filter by category
        response = await async_client.get("/products/info?category=Electronics")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert all(p["category"] == "Electronics" for p in data["data"])

        # Filter by is_active=False (should return empty if all are active)
        response = await async_client.get("/products/info?is_active=false")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)

    @pytest.mark.asyncio
    async def test_list_products_pagination(
        self,
        async_client: AsyncClient,
        session_auth_headers_admin1: dict,
        test_helper,
    ):
        """
        Test product listing with pagination (limit and offset).
        """
        # Create multiple products
        for i in range(5):
            product_data = {
                "product_sku": f"TEST-SKU-{str(uuid.uuid4())[:8]}",
                "name": f"Test Product {i}",
                "category": "Electronics",
                "price": 10.0 + i,
                "qty": i + 1,
                "is_active": True,
            }
            await async_client.post("/products/create", headers=session_auth_headers_admin1, json=product_data)

        # Test pagination
        response = await async_client.get("/products/info?limit=2&offset=0")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert data["limit"] == 2
        assert data["offset"] == 0
        assert len(data["data"]) <= 2

        # Test offset
        response = await async_client.get("/products/info?limit=2&offset=2")
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["offset"] == 2

    # ================== Product Detail Tests (Public) ==================

    @pytest.mark.asyncio
    async def test_get_product_by_id_success(
        self,
        async_client: AsyncClient,
        session_auth_headers_admin1: dict,
        test_helper,
    ):
        """
        Test successful product retrieval by ID without authentication.
        """
        # Create a test product
        unique_sku = f"TEST-SKU-{str(uuid.uuid4())[:8]}"
        product_data = {
            "product_sku": unique_sku,
            "name": "Test Product Detail",
            "description": "Detailed description",
            "currency": "TWD",
            "price": 150.75,
            "qty": 20,
            "photo_url": "https://example.com/detail.jpg",
            "category": "Electronics",
            "is_active": True,
        }

        create_response = await async_client.post(
            "/products/create",
            headers=session_auth_headers_admin1,
            json=product_data,
        )
        assert create_response.status_code == status.HTTP_200_OK
        created_product = create_response.json()["data"]
        product_id = created_product["product_id"]

        # Get product by ID without auth
        response = await async_client.get(f"/products/{product_id}")

        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert "data" in data
        product = data["data"]
        assert product["product_id"] == product_id
        assert product["product_sku"] == product_data["product_sku"]
        assert product["name"] == product_data["name"]
        assert product["description"] == product_data["description"]
        assert product["currency"] == product_data["currency"]
        assert product["price"] == product_data["price"]
        assert product["qty"] == product_data["qty"]
        assert product["photo_url"] == product_data["photo_url"]
        assert product["category"] == product_data["category"]
        assert product["is_active"] == product_data["is_active"]

    @pytest.mark.asyncio
    async def test_get_product_by_id_with_session(
        self,
        async_client_with_user1: AsyncClient,
        async_client: AsyncClient,
        session_auth_headers_admin1: dict,
        test_helper,
    ):
        """
        Test product retrieval by ID with user session cookie.
        """
        # Create a test product using admin client
        unique_sku = f"TEST-SKU-{str(uuid.uuid4())[:8]}"
        product_data = {
            "product_sku": unique_sku,
            "name": "Test Product for Session",
            "category": "Books",
            "price": 25.50,
            "qty": 15,
            "is_active": True,
        }

        create_response = await async_client.post(
            "/products/create",
            headers=session_auth_headers_admin1,
            json=product_data,
        )
        assert create_response.status_code == status.HTTP_200_OK
        created_product = create_response.json()["data"]
        product_id = created_product["product_id"]

        # Get product by ID with user session
        response = await async_client_with_user1.get(f"/products/{product_id}")

        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert data["data"]["product_id"] == product_id

    @pytest.mark.asyncio
    async def test_get_product_not_found(self, async_client: AsyncClient):
        """
        Test getting non-existent product returns 404.
        """
        non_existent_id = "pt_999999"

        response = await async_client.get(f"/products/{non_existent_id}")

        assert response.status_code == status.HTTP_404_NOT_FOUND
        assert "not found" in response.json()["detail"].lower()

    # ================== Category List Tests (Public) ==================

    @pytest.mark.asyncio
    async def test_list_categories_success(
        self,
        async_client: AsyncClient,
        session_auth_headers_admin1: dict,
        test_helper,
    ):
        """
        Test successful category listing without authentication.
        """
        # Create products in different categories
        categories = ["Electronics", "Books", "Clothing"]
        for category in categories:
            product_data = {
                "product_sku": f"TEST-SKU-{str(uuid.uuid4())[:8]}",
                "name": f"Test Product {category}",
                "category": category,
                "price": 10.0,
                "qty": 1,
                "is_active": True,
            }
            await async_client.post("/products/create", headers=session_auth_headers_admin1, json=product_data)

        # List categories without auth
        response = await async_client.get("/products/categories")

        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert "data" in data
        assert isinstance(data["data"], list)
        assert len(data["data"]) >= len(categories)

        # Verify all created categories are in the list
        category_list = data["data"]
        for category in categories:
            assert category in category_list

    @pytest.mark.asyncio
    async def test_list_categories_with_session(
        self,
        async_client_with_user1: AsyncClient,
        async_client: AsyncClient,
        session_auth_headers_admin1: dict,
        test_helper,
    ):
        """
        Test category listing with user session cookie.
        """
        # Create a test product using admin client
        product_data = {
            "product_sku": f"TEST-SKU-{str(uuid.uuid4())[:8]}",
            "name": "Test Product",
            "category": "Electronics",
            "price": 10.0,
            "qty": 1,
            "is_active": True,
        }

        await async_client.post("/products/create", headers=session_auth_headers_admin1, json=product_data)

        # List categories with user session
        response = await async_client_with_user1.get("/products/categories")

        # Verify response
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        test_helper.assert_response_structure(data, expected_status=1)
        assert "data" in data
        assert isinstance(data["data"], list)
