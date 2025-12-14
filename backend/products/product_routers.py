"""
Product Routers - Product API endpoints

Provides endpoints for:
- GET / - List products (public, rate limited)
- GET /{product_id} - Get product by ID (public, rate limited)
- POST / - Create product (access_token auth, staff only)
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.auth.auth_services import get_current_admin_token
from backend.products.product_models import (
    CategoryListResponse,
    ProductCreateRequest,
    ProductListResponse,
    SingleProductResponse,
)
from backend.products.product_services import product_service

router = APIRouter(prefix="/products", tags=["products"])

# Rate limiter instance - uses same key_func as main.py
limiter = Limiter(key_func=get_remote_address)


# ================== Public Endpoints (Rate Limited) ==================


@router.get("/", response_model=ProductListResponse)
@limiter.limit("60/minute")
async def list_products(
    request: Request,
    category: Optional[str] = Query(None, description="Filter by category"),
    is_active: Optional[bool] = Query(True, description="Filter by active status"),
    limit: int = Query(50, ge=1, le=100, description="Number of items per page"),
    offset: int = Query(0, ge=0, description="Number of items to skip"),
) -> ProductListResponse:
    """
    List products with optional filtering and pagination.
    Public endpoint with rate limiting (60 requests per minute per IP).
    """
    return await product_service.list_products_response(
        category=category,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )


@router.get("/categories", response_model=CategoryListResponse)
@limiter.limit("60/minute")
async def list_categories(
    request: Request,
) -> CategoryListResponse:
    """
    Get list of product categories.
    Public endpoint with rate limiting (60 requests per minute per IP).
    """
    return await product_service.get_categories_response()


@router.get("/{product_id}", response_model=SingleProductResponse)
@limiter.limit("60/minute")
async def get_product(
    request: Request,
    product_id: str,
) -> SingleProductResponse:
    """
    Get product by ID.
    Public endpoint with rate limiting (60 requests per minute per IP).
    """
    try:
        return await product_service.get_product_by_id_response(product_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )


# ================== Access Token Protected Endpoints (Staff Only) ==================


@router.post("/", response_model=SingleProductResponse)
async def create_product(
    body: ProductCreateRequest,
    current_admin: dict = Depends(get_current_admin_token),
) -> SingleProductResponse:
    """
    Create a new product.
    Requires access token authentication (Bearer token, admin only).
    """
    try:
        return await product_service.create_product_response(body)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
