"""Scope validation preview endpoint.

Lets the UI show whether a target is acceptable before enqueueing a scan.
"""
from fastapi import APIRouter
from pydantic import BaseModel

from app.schemas import ScopeAuthorization
from app.security.scope import (
    MetadataEndpointError,
    OutOfScopeError,
    PrivateNetworkError,
    ScopeValidator,
)

router = APIRouter(prefix="/scope", tags=["scope"])


class ScopeRequest(BaseModel):
    target: str
    allow_private_networks: bool = False


@router.post("/validate", response_model=ScopeAuthorization)
async def validate_scope(req: ScopeRequest) -> ScopeAuthorization:
    try:
        validator = ScopeValidator.for_target(
            req.target, allow_private_networks=req.allow_private_networks
        )
        normalized = validator.assert_in_scope(req.target)
        return ScopeAuthorization(
            target=req.target,
            authorized=True,
            normalized=normalized,
            reason=f"Scope authorized for {normalized} and all subdomains.",
        )
    except (OutOfScopeError, PrivateNetworkError, MetadataEndpointError) as exc:
        return ScopeAuthorization(
            target=req.target,
            authorized=False,
            normalized=req.target.lower(),
            reason=str(exc),
        )
