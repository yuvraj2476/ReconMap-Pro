"""DNS record enumeration.

Passively collects A, AAAA, CNAME, MX, NS, TXT, SOA and DMARC records using
dnspython. All queried names must be inside the authorized scope.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, List

import dns.asyncresolver
import dns.exception

from app.security.scope import ScopeValidator

logger = logging.getLogger(__name__)

RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


@dataclass
class DnsResult:
    domain: str
    records: Dict[str, List[str]] = field(default_factory=dict)
    dmarc: List[str] = field(default_factory=list)

    @property
    def all_ipv4(self) -> List[str]:
        return list(self.records.get("A", []))

    @property
    def all_ipv6(self) -> List[str]:
        return list(self.records.get("AAAA", []))

    @property
    def all_ips(self) -> List[str]:
        return self.all_ipv4 + self.all_ipv6


async def _query(resolver: dns.asyncresolver.Resolver, name: str, rtype: str) -> List[str]:
    try:
        answer = await resolver.resolve(name, rtype)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException as exc:
        logger.debug("DNS %s query for %s failed: %s", rtype, name, exc)
        return []

    values: List[str] = []
    for r in answer:
        if rtype in ("A", "AAAA"):
            values.append(str(r))
        elif rtype == "MX":
            values.append(f"{r.preference} {r.exchange.to_text().rstrip('.')}")
        elif rtype == "NS":
            values.append(str(r.target).rstrip("."))
        elif rtype == "CNAME":
            values.append(str(r.target).rstrip("."))
        elif rtype == "TXT":
            # TXT records can be split into multiple strings.
            values.append("".join(s.decode("utf-8", "replace") for s in r.strings))
        elif rtype == "SOA":
            values.append(
                f"{r.mname} {r.rname} serial={r.serial} refresh={r.refresh}"
            )
        else:
            values.append(str(r))
    return values


async def enumerate_dns(domain: str, validator: ScopeValidator) -> DnsResult:
    """Enumerate DNS records for an in-scope domain."""
    name = validator.assert_in_scope(domain)
    resolver = validator._resolver  # noqa: SLF001 - controlled internal
    result = DnsResult(domain=name)

    for rtype in RECORD_TYPES:
        if rtype in ("A", "AAAA"):
            # Use the validator's resolve() which falls back to getaddrinfo
            # (and thus /etc/hosts) so the local Docker lab works.
            if rtype == "A":
                result.records["A"] = [
                    ip for ip in await validator.resolve(name)
                    if ":" not in ip
                ]
            else:
                result.records["AAAA"] = [
                    ip for ip in await validator.resolve(name)
                    if ":" in ip
                ]
        else:
            result.records[rtype] = await _query(resolver, name, rtype)

    # DMARC record (_dmarc.<domain>)
    dmarc = await _query(resolver, f"_dmarc.{name}", "TXT")
    if dmarc:
        result.dmarc = dmarc

    # Validate any resolved IPs are not metadata/private (for active stages).
    # We do not raise here because DNS enumeration itself is passive; the
    # validator is applied again before any HTTP request.
    logger.info("DNS enumeration for %s found %d IPs", name, len(result.all_ips))
    return result
