"""
FastAPI Application Entry Point
"""

from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from scalar_fastapi import get_scalar_api_reference
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from backend.core.db_manager import close_database, init_database
from backend.core.environment import env_config

from backend.auth.auth_routers import router as auth_router
from backend.users.user_routers import router as user_router
from backend.products.product_routers import router as product_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown events."""
    # Startup
    await init_database()
    yield
    # Shutdown
    await close_database()


app = FastAPI(
    title="Backend API",
    description="FastAPI Backend with Session and Access Token Authentication",
    version="1.0.0",
    lifespan=lifespan,
)

# Initialize rate limiter with the app
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=env_config.get("cors_origins", ["*"]),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(product_router)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "environment": env_config.environment.value}


# Scalar API Documentation
@app.get("/scalar", include_in_schema=False)
async def scalar_html():
    """
    Scalar API Documentation endpoint.
    Access at: http://localhost:8000/scalar
    """
    return get_scalar_api_reference(
        openapi_url=app.openapi_url,
        title=app.title + " - Scalar API Documentation",
    )


if __name__ == "__main__":
    # Get configuration from environment variables or use defaults
    
    # Run the server
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )

