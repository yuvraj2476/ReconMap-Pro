"""Health check and policy endpoints."""
from fastapi import APIRouter

from app.config import get_settings
from app.schemas import PolicyResponse
from app.security.policies import describe_policies

router = APIRouter(tags=["system"])


@router.get("/health")
async def health() -> dict:
    settings = get_settings()
    return {
        "status": "ok",
        "app": settings.app_name,
        "environment": settings.environment,
        "database": settings.database_url.split("://", 1)[0],
        "redis": "configured" if settings.redis_url else "in-process",
        "allow_private_networks": settings.allow_private_networks,
        "allow_tool_download": settings.allow_tool_download,
    }


@router.get("/policies", response_model=PolicyResponse)
async def policies() -> PolicyResponse:
    p = describe_policies()
    return PolicyResponse(**p)
