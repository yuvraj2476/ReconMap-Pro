"""Scope validation and SSRF protection.

Every active HTTP/DNS request issued by ReconMap Pro MUST pass through
:class:`ScopeValidator`. The validator enforces:

1. The target hostname is inside an explicitly authorized scope.
2. The hostname does not resolve to a loopback / private / link-local /
   reserved IP address (prevents SSRF against internal services).
3. Cloud metadata endpoints (169.254.169.254, fd00:ec2::254, etc.) are
   unconditionally blocked regardless of other flags.
4. Internationalised / confusing names are normalised before comparison.

These checks cannot be bypassed by the user-facing API; they are also the
unit-tested boundary that guarantees the platform cannot be used to attack
internal or non-consenting targets.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Set, Tuple
from urllib.parse import urlparse

import dns.asyncresolver
import idna

logger = logging.getLogger(__name__)

# Cloud instance metadata services. Blocked UNCONDITIONALLY.
_METADATA_IPS: Set[str] = {
    "169.254.169.254",   # AWS / GCP / Azure / Oracle / DigitalOcean
    "169.254.170.2",     # AWS ECS task metadata
    "fd00:ec2::254",     # AWS IMDSv6
    "100.100.100.200",   # Alibaba Cloud metadata
}
_METADATA_HOSTNAMES: Set[str] = {
    "metadata.google.internal",
    "metadata",
    "metadata.azure.com",
    "169.254.169.254",
}


class ScopeError(Exception):
    """Base class for scope violations."""

    code = "scope_error"


class OutOfScopeError(ScopeError):
    code = "out_of_scope"


class PrivateNetworkError(ScopeError):
    code = "private_network"


class MetadataEndpointError(ScopeError):
    code = "metadata_endpoint"


class ResolutionError(ScopeError):
    code = "resolution_failed"


@dataclass(frozen=True)
class Scope:
    """An authorized scope.

    A scope is represented as a registrable domain (e.g. ``example.com``) plus
    an optional set of explicit additional hostnames. All subdomains of the
    registrable domain are considered in scope.
    """

    root_domain: str
    include_subdomains: bool = True
    additional_hosts: Tuple[str, ...] = field(default_factory=tuple)

    def contains(self, hostname: str) -> bool:
        host = _normalize_hostname(hostname)
        if host == self.root_domain:
            return True
        if any(host == h for h in self.additional_hosts):
            return True
        if self.include_subdomains and host.endswith("." + self.root_domain):
            return True
        return False


def _normalize_hostname(hostname: str) -> str:
    """Lower-case, strip trailing dot/port, and IDNA-encode."""
    if not hostname:
        return ""
    hostname = hostname.strip().lower()
    # Strip scheme if a URL was accidentally passed.
    if "://" in hostname:
        hostname = urlparse(hostname).hostname or ""
    # Strip port
    if ":" in hostname and not hostname.startswith("["):
        hostname = hostname.split(":", 1)[0]
    hostname = hostname.rstrip(".")
    try:
        hostname = idna.encode(hostname).decode("ascii")
    except (idna.IDNAError, UnicodeError):
        # Leave as-is; comparison will simply fail to match.
        pass
    return hostname


def _is_blocked_ip(ip: str) -> Optional[str]:
    """Return a reason string if the IP is unsafe, else None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "invalid-ip"

    if str(addr) in _METADATA_IPS:
        return "cloud-metadata"

    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    if addr.is_unspecified:
        return "unspecified"
    # is_private covers RFC1918 (10/8, 172.16/12, 192.168/16), CGNAT 100.64/10,
    # and several v6 unique-local ranges.
    if addr.is_private:
        return "private"
    return None


class ScopeValidator:
    """Validates hostnames and URLs against an authorized scope.

    Parameters
    ----------
    scopes:
        Iterable of :class:`Scope` objects. Typically constructed from the
        scan target the user explicitly authorized.
    allow_private_networks:
        When True, non-metadata private/loopback IPs are permitted. This is
        only used when targeting the bundled local Docker lab. Metadata IPs
        remain blocked unconditionally.
    resolver:
        Optional injected dnspython resolver (for tests).
    """

    def __init__(
        self,
        scopes: Iterable[Scope],
        allow_private_networks: bool = False,
        resolver: Optional[dns.asyncresolver.Resolver] = None,
    ) -> None:
        self.scopes: List[Scope] = list(scopes)
        self.allow_private_networks = allow_private_networks
        self._resolver = resolver or dns.asyncresolver.Resolver()
        self._resolver.timeout = 5.0
        self._resolver.lifetime = 8.0
        self._cache: dict[str, List[str]] = {}

    # ------------------------------------------------------------------ #
    # Construction helpers
    # ------------------------------------------------------------------ #
    @classmethod
    def for_target(
        cls,
        target: str,
        allow_private_networks: bool = False,
        extra_scopes: Optional[Iterable[Scope]] = None,
    ) -> "ScopeValidator":
        """Build a validator for a single authorized target domain.

        Rejects raw IP addresses and cloud-metadata hostnames as scan targets:
        a scan target must be a domain name that the operator is authorized to
        test. IP-level blocking is still enforced at every request, but
        rejecting them at the entry point prevents the scan from even
        attempting to resolve a metadata endpoint.
        """
        root = _normalize_hostname(target)
        if not root:
            raise ValueError("target must not be empty")

        # Reject raw IP addresses (v4 or v6)
        try:
            ipaddress.ip_address(root)
            raise ValueError(
                "Scan targets must be domain names, not raw IP addresses. "
                f"({root!r} looks like an IP)"
            )
        except ValueError as exc:
            if "must be domain names" in str(exc):
                raise
            # Not an IP - that's fine, fall through

        if root in _METADATA_HOSTNAMES:
            raise ValueError(
                f"Refusing to target cloud-metadata endpoint {root!r}"
            )

        scopes = [Scope(root_domain=root, include_subdomains=True)]
        if extra_scopes:
            scopes.extend(extra_scopes)
        return cls(scopes, allow_private_networks=allow_private_networks)

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def is_in_scope(self, hostname: str) -> bool:
        host = _normalize_hostname(hostname)
        return any(s.contains(host) for s in self.scopes)

    def assert_in_scope(self, hostname: str) -> str:
        """Raise if hostname is out of scope; return normalized hostname."""
        host = _normalize_hostname(hostname)
        if not self.is_in_scope(host):
            raise OutOfScopeError(
                f"Host {host!r} is not within the authorized scope: "
                f"{[s.root_domain for s in self.scopes]}"
            )
        return host

    async def resolve(self, hostname: str) -> List[str]:
        """Resolve hostname to A/AAAA records, with caching.

        Queries DNS via dnspython, and if that returns nothing, falls back to
        the OS resolver (``getaddrinfo``) which honours ``/etc/hosts`` — this
        is what allows the local Docker lab to be scanned.
        """
        host = _normalize_hostname(hostname)
        if host in self._cache:
            return self._cache[host]
        ips: List[str] = []
        try:
            answers = await self._resolver.resolve(host, "A")
            ips.extend(str(r) for r in answers)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as exc:  # pragma: no cover - network dependent
            logger.debug("A record resolution failed for %s: %s", host, exc)
        try:
            answers = await self._resolver.resolve(host, "AAAA")
            ips.extend(str(r) for r in answers)
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as exc:  # pragma: no cover
            logger.debug("AAAA resolution failed for %s: %s", host, exc)

        # Fall back to the OS resolver (reads /etc/hosts, mDNS, etc.). This is
        # essential for the local Docker lab, where hostnames are defined via
        # container aliases or /etc/hosts rather than public DNS.
        if not ips:
            try:
                loop = asyncio.get_running_loop()
                infos = await loop.getaddrinfo(host, None)
                for family, _type, _proto, _canon, sockaddr in infos:
                    ip = sockaddr[0]
                    # Strip zone id from IPv6
                    if "%" in ip:
                        ip = ip.split("%", 1)[0]
                    if ip not in ips:
                        ips.append(ip)
            except Exception as exc:
                logger.debug("getaddrinfo fallback failed for %s: %s", host, exc)

        if not ips and (self.allow_private_networks or host == "localhost" or host.endswith(".local") or host.endswith(".lab")):
            ips.append("127.0.0.1")

        self._cache[host] = ips
        return ips

    async def validate_host(self, hostname: str) -> Tuple[str, List[str]]:
        """Full validation: scope + DNS + IP safety.

        Returns the normalized hostname and resolved IP list. Raises a
        :class:`ScopeError` subclass on any violation.
        """
        host = self.assert_in_scope(hostname)

        if host in _METADATA_HOSTNAMES:
            raise MetadataEndpointError(
                f"Blocked request to cloud metadata endpoint {host!r}"
            )

        ips = await self.resolve(host)
        if not ips:
            # Some scans (DNS enumeration) may want to record unresolvable
            # hosts; the caller decides. We raise for active HTTP requests.
            raise ResolutionError(f"Could not resolve {host!r}")

        for ip in ips:
            reason = _is_blocked_ip(ip)
            if reason == "cloud-metadata":
                raise MetadataEndpointError(
                    f"Blocked request to cloud metadata IP {ip} (from {host})"
                )
            if reason and not self.allow_private_networks:
                raise PrivateNetworkError(
                    f"Refusing to contact {host!r}: resolved to {reason} address {ip}. "
                    "Set allow_private_networks=True only for the local Docker lab."
                )
        return host, ips

    async def validate_url(self, url: str) -> Tuple[str, str, List[str]]:
        """Validate an absolute URL. Returns (hostname, url, ips)."""
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise OutOfScopeError(f"Only http/https URLs are supported, got {parsed.scheme!r}")
        if not parsed.hostname:
            raise OutOfScopeError("URL has no hostname")
        host, ips = await self.validate_host(parsed.hostname)
        return host, url, ips

    def validate_ip_direct(self, ip: str) -> None:
        """Explicitly validate a raw IP address (blocks metadata always)."""
        reason = _is_blocked_ip(ip)
        if reason == "cloud-metadata":
            raise MetadataEndpointError(f"Blocked metadata IP {ip}")
        if reason and not self.allow_private_networks:
            raise PrivateNetworkError(
                f"Refusing direct access to {reason} IP {ip}"
            )


def host_from_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower()
