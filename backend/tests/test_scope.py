"""Scope validation and SSRF protection tests."""
from __future__ import annotations

import pytest

from app.security.scope import (
    MetadataEndpointError,
    OutOfScopeError,
    PrivateNetworkError,
    Scope,
    ScopeValidator,
    _is_blocked_ip,
    _normalize_hostname,
)


# --------------------------------------------------------------------------- #
# Hostname normalization
# --------------------------------------------------------------------------- #
def test_normalize_lowercases_and_strips_port():
    assert _normalize_hostname("Example.COM:443") == "example.com"
    assert _normalize_hostname("EXAMPLE.com.") == "example.com"


def test_normalize_handles_url():
    assert _normalize_hostname("https://www.Example.COM/path") == "www.example.com"


# --------------------------------------------------------------------------- #
# IP blocking
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
    "169.254.169.254", "0.0.0.0", "::1", "fe80::1", "224.0.0.1",
])
def test_private_and_special_ips_are_blocked(ip):
    assert _is_blocked_ip(ip) is not None


@pytest.mark.parametrize("ip", [
    "8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946",
])
def test_public_ips_are_allowed(ip):
    assert _is_blocked_ip(ip) is None


def test_metadata_ip_always_blocked_even_with_private_flag():
    v = ScopeValidator([Scope("example.com")], allow_private_networks=True)
    with pytest.raises(MetadataEndpointError):
        v.validate_ip_direct("169.254.169.254")


def test_loopback_blocked_by_default():
    v = ScopeValidator([Scope("example.com")], allow_private_networks=False)
    with pytest.raises(PrivateNetworkError):
        v.validate_ip_direct("127.0.0.1")


def test_loopback_allowed_when_private_flag_set():
    v = ScopeValidator([Scope("example.com")], allow_private_networks=True)
    v.validate_ip_direct("127.0.0.1")  # no exception


# --------------------------------------------------------------------------- #
# Scope membership
# --------------------------------------------------------------------------- #
def test_root_domain_and_subdomains_in_scope():
    v = ScopeValidator.for_target("example.com")
    assert v.is_in_scope("example.com")
    assert v.is_in_scope("www.example.com")
    assert v.is_in_scope("a.b.c.example.com")


def test_out_of_scope_domain_rejected():
    v = ScopeValidator.for_target("example.com")
    assert not v.is_in_scope("evil.com")
    assert not v.is_in_scope("example.com.evil.com")
    assert not v.is_in_scope("notexample.com")


def test_assert_in_scope_raises():
    v = ScopeValidator.for_target("example.com")
    with pytest.raises(OutOfScopeError):
        v.assert_in_scope("evil.com")


def test_metadata_hostname_blocked():
    v = ScopeValidator([Scope("google.internal")], allow_private_networks=True)
    with pytest.raises(MetadataEndpointError):
        import asyncio
        asyncio.get_event_loop().run_until_complete(
            v.validate_host("metadata.google.internal")
        )


# --------------------------------------------------------------------------- #
# URL validation
# --------------------------------------------------------------------------- #
def test_validate_url_rejects_non_http_scheme():
    v = ScopeValidator.for_target("example.com")
    import asyncio
    with pytest.raises(OutOfScopeError):
        asyncio.get_event_loop().run_until_complete(
            v.validate_url("file:///etc/passwd")
        )
    with pytest.raises(OutOfScopeError):
        asyncio.get_event_loop().run_until_complete(
            v.validate_url("gopher://example.com")
        )


def test_validate_url_rejects_out_of_scope():
    v = ScopeValidator.for_target("example.com")
    import asyncio
    with pytest.raises(OutOfScopeError):
        asyncio.get_event_loop().run_until_complete(
            v.validate_url("https://evil.com/")
        )


def test_raw_ip_target_rejected():
    """Scan targets must be domain names, not raw IPs (prevents metadata targeting)."""
    with pytest.raises(ValueError, match="domain names"):
        ScopeValidator.for_target("169.254.169.254")
    with pytest.raises(ValueError, match="domain names"):
        ScopeValidator.for_target("10.0.0.1")


def test_metadata_hostname_target_rejected():
    with pytest.raises(ValueError, match="metadata"):
        ScopeValidator.for_target("metadata.google.internal")
