"""
Product Models - Pydantic schemas for product operations
"""

from datetime import datetime as dt
from typing import Optional

from pydantic import BaseModel, Field


# ================== Request Models ==================

class ProductCreateRequest(BaseModel):
    """Product creation request body (staff only)."""
    product_sku: str = Field(..., min_length=1, max_length=50)
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    currency: str = Field(default="TWD", max_length=3)
    price: float = Field(default=0, ge=0)
    qty: int = Field(default=0, ge=0)
    photo_url: Optional[str] = None
    category: str = Field(..., min_length=1, max_length=100)
    is_active: bool = True


class ProductUpdateRequest(BaseModel):
    """Product update request body (staff only)."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    currency: Optional[str] = Field(None, max_length=3)
    price: Optional[float] = Field(None, ge=0)
    qty: Optional[int] = Field(None, ge=0)
    photo_url: Optional[str] = None
    category: Optional[str] = Field(None, min_length=1, max_length=100)
    is_active: Optional[bool] = None


class ProductListQuery(BaseModel):
    """Query parameters for product listing."""
    category: Optional[str] = None
    is_active: Optional[bool] = True
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


# ================== Response Models ==================

class ProductResponse(BaseModel):
    """Single product response."""
    product_id: str
    product_sku: str
    name: str
    description: Optional[str] = None
    currency: str
    price: float
    qty: int
    photo_url: Optional[str] = None
    category: str
    is_active: bool
    created_at: dt
    updated_at: dt


class ProductListItemResponse(BaseModel):
    """Product item in list response (minimal fields)."""
    product_id: str
    product_sku: str
    name: str
    price: float
    qty: int
    photo_url: Optional[str] = None
    category: str
    is_active: bool


class SingleProductResponse(BaseModel):
    """Standard single product response wrapper."""
    status: int = 1
    message: str
    data: ProductResponse


class ProductListResponse(BaseModel):
    """Product list response wrapper."""
    status: int = 1
    message: str
    data: list[ProductListItemResponse]
    total: int
    limit: int
    offset: int


class CategoryListResponse(BaseModel):
    """Category list response wrapper."""
    status: int = 1
    message: str
    data: list[str]


# ================== Internal Models ==================

class ProductCreate(BaseModel):
    """Internal model for creating a product."""
    product_id: str
    product_sku: str
    name: str
    description: Optional[str] = None
    currency: str = "TWD"
    price: float = 0
    qty: int = 0
    photo_url: Optional[str] = None
    category: str
    is_active: bool = True
    created_at: dt
    updated_at: dt

