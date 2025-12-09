"""
Product Routers - Product API endpoints

Provides endpoints for:
- GET / - List products (api_key auth)
- GET /{product_id} - Get product by ID (api_key auth)
- POST / - Create product (access_token auth, staff only)
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.auth.auth_services import get_current_user_token, verify_api_key
from backend.products.product_models import (
    ProductCreateRequest,
    ProductListItemResponse,
    ProductListResponse,
    ProductResponse,
    SingleProductResponse,
)
from backend.products.product_services import product_service

router = APIRouter(prefix="/products", tags=["products"])


# ================== API Key Protected Endpoints (Public) ==================

@router.get("/", response_model=ProductListResponse)
async def list_products(
    category: Optional[str] = Query(None, description="Filter by category"),
    is_active: Optional[bool] = Query(True, description="Filter by active status"),
    limit: int = Query(50, ge=1, le=100, description="Number of items per page"),
    offset: int = Query(0, ge=0, description="Number of items to skip"),
    api_key: dict = Depends(verify_api_key),
) -> ProductListResponse:
    """
    List products with optional filtering and pagination.
    Requires API key authentication (X-API-Key header).
    """
    products, total = await product_service.list_products(
        category=category,
        is_active=is_active,
        limit=limit,
        offset=offset,
    )

    return ProductListResponse(
        status=1,
        message="Products retrieved",
        data=[
            ProductListItemResponse(
                product_id=p["product_id"],
                product_sku=p["product_sku"],
                name=p["name"],
                price=p["price"],
                qty=p["qty"],
                photo_url=p.get("photo_url"),
                category=p["category"],
                is_active=p["is_active"],
            )
            for p in products
        ],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/categories")
async def list_categories(
    api_key: dict = Depends(verify_api_key),
) -> dict:
    """
    Get list of product categories.
    Requires API key authentication (X-API-Key header).
    """
    categories = await product_service.get_categories()
    
    return {
        "status": 1,
        "message": "Categories retrieved",
        "data": categories,
    }


@router.get("/{product_id}", response_model=SingleProductResponse)
async def get_product(
    product_id: str,
    api_key: dict = Depends(verify_api_key),
) -> SingleProductResponse:
    """
    Get product by ID.
    Requires API key authentication (X-API-Key header).
    """
    product = await product_service.get_product_by_id(product_id)
    if not product:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Product not found",
        )

    return SingleProductResponse(
        status=1,
        message="Product retrieved",
        data=ProductResponse(
            product_id=product["product_id"],
            product_sku=product["product_sku"],
            name=product["name"],
            description=product.get("description"),
            currency=product["currency"],
            price=product["price"],
            qty=product["qty"],
            photo_url=product.get("photo_url"),
            category=product["category"],
            is_active=product["is_active"],
            created_at=product["created_at"],
            updated_at=product["updated_at"],
        ),
    )


# ================== Access Token Protected Endpoints (Staff Only) ==================

@router.post("/", response_model=SingleProductResponse)
async def create_product(
    body: ProductCreateRequest,
    current_user: dict = Depends(get_current_user_token),
) -> SingleProductResponse:
    """
    Create a new product.
    Requires access token authentication (Bearer token, staff only).
    """
    try:
        product = await product_service.create_product(body)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    return SingleProductResponse(
        status=1,
        message="Product created successfully",
        data=ProductResponse(
            product_id=product["product_id"],
            product_sku=product["product_sku"],
            name=product["name"],
            description=product.get("description"),
            currency=product["currency"],
            price=product["price"],
            qty=product["qty"],
            photo_url=product.get("photo_url"),
            category=product["category"],
            is_active=product["is_active"],
            created_at=product["created_at"],
            updated_at=product["updated_at"],
        ),
    )

