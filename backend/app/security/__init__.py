"""Security primitives for ReconMap Pro.

This package enforces the authorization-first security model:

* :mod:`scope`       - validates that every active request targets an authorized
                       in-scope domain and a public IP address (SSRF protection).
* :mod:`ratelimiter` - a token-bucket/leaky rate limiter (Redis or in-memory).
* :mod:`policies`    - high-level guardrails describing what the platform will
                       and will not do.
"""
from app.security.scope import (
    ScopeError,
    OutOfScopeError,
    PrivateNetworkError,
    MetadataEndpointError,
    ResolutionError,
    ScopeValidator,
)
from app.security.policies import ALLOWED, BLOCKED, describe_policies

__all__ = [
    "ScopeError",
    "OutOfScopeError",
    "PrivateNetworkError",
    "MetadataEndpointError",
    "ResolutionError",
    "ScopeValidator",
    "ALLOWED",
    "BLOCKED",
    "describe_policies",
]
