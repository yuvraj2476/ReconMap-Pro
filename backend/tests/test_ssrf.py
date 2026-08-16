"""Integration-style tests proving the HTTP client blocks SSRF."""
from __future__ import annotations

import asyncio

import pytest

from app.config import Settings
from app.recon.http_client import SafeHttpClient
from app.security.scope import (
    MetadataEndpointError,
    OutOfScopeError,
    PrivateNetworkError,
    Scope,
    ScopeValidator,
)


@pytest.fixture
def settings():
    return Settings(
        database_url="sqlite+aiosqlite:///./test_ssrf.db",
        report_dir="./test_reports",
    )


@pytest.mark.asyncio
async def test_client_blocks_out_of_scope(settings):
    v = ScopeValidator.for_target("example.com")
    async with SafeHttpClient(v, settings) as client:
        # This must NOT perform a request
        result = await client.get("https://evil.com/")
        assert result is None


@pytest.mark.asyncio
async def test_client_blocks_metadata_ip():
    v = ScopeValidator(
        [Scope("169.254.169.254")],  # artificially in-scope...
        allow_private_networks=True,
    )
    # ...but metadata is blocked unconditionally regardless of scope.
    with pytest.raises(MetadataEndpointError):
        await v.validate_host("169.254.169.254")


@pytest.mark.asyncio
async def test_client_blocks_loopback_by_default(settings):
    # Even if an operator authorizes a hostname, the validator must refuse
    # to contact it when it resolves to a loopback address.
    v = ScopeValidator(
        [Scope("127.0.0.1.nip.io")], allow_private_networks=False
    )
    # nip.io resolves 127.0.0.1.nip.io -> 127.0.0.1
    with pytest.raises((PrivateNetworkError,)):
        await v.validate_host("127.0.0.1.nip.io")


def test_validator_blocks_direct_loopback_ip(settings):
    v = ScopeValidator([Scope("example.com")], allow_private_networks=False)
    with pytest.raises(PrivateNetworkError):
        v.validate_ip_direct("127.0.0.1")
