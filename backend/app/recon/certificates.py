"""Certificate discovery.

Fetches TLS certificate metadata from hosts that present one, and aggregates
certificate-transparency results from crt.sh. No exploitation; purely metadata.
"""
from __future__ import annotations

import logging
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional

from app.security.scope import ScopeValidator

logger = logging.getLogger(__name__)


@dataclass
class CertificateInfo:
    hostname: str
    issuer: Optional[str] = None
    subject: Optional[str] = None
    serial: Optional[str] = None
    not_before: Optional[str] = None
    not_after: Optional[str] = None
    san: List[str] = field(default_factory=list)
    version: Optional[int] = None
    signature_algorithm: Optional[str] = None
    error: Optional[str] = None

    @property
    def expired(self) -> bool:
        if not self.not_after:
            return False
        try:
            return datetime.utcnow() > datetime.fromisoformat(self.not_after)
        except ValueError:
            return False


async def fetch_certificate(
    hostname: str, validator: ScopeValidator, *, port: int = 443, timeout: float = 8.0
) -> CertificateInfo:
    """Fetch TLS certificate metadata for an in-scope host."""
    host, ips = await validator.validate_host(hostname)
    info = CertificateInfo(hostname=host)
    # Use the first resolved IP but verify the hostname via SNI.
    ip = ips[0] if ips else host

    try:
        import asyncio

        async def _get_cert():
            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            # asyncio's open_connection uses getaddrinfo internally; because we
            # already validated the IP we connect to the IP and pass server_hostname.
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port, ssl=ctx, server_hostname=host),
                timeout=timeout,
            )
            cert = writer.get_extra_info("ssl_object").getpeercert()
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return cert

        cert = await _get_cert()
        if not cert:
            info.error = "no-certificate"
            return info

        info.issuer = _name_to_str(cert.get("issuer"))
        info.subject = _name_to_str(cert.get("subject"))
        info.serial = cert.get("serialNumber")
        info.not_before = cert.get("notBefore")
        info.not_after = cert.get("notAfter")
        info.version = cert.get("version")
        info.signature_algorithm = cert.get("signatureAlgorithm")
        san = cert.get("subjectAltName") or []
        info.san = sorted({v for _k, v in san})
    except ssl.SSLCertVerificationError as exc:
        info.error = f"cert-verify-error: {exc.verify_message}"
    except (TimeoutError, OSError, ConnectionError) as exc:
        info.error = f"connection-error: {exc}"
    except Exception as exc:  # pragma: no cover
        info.error = f"error: {exc}"
    return info


def _name_to_str(name) -> Optional[str]:
    if not name:
        return None
    # dnspython/ssl returns tuples of ((key, value),)
    try:
        return ", ".join(f"{k}={v}" for rdn in name for k, v in rdn)
    except Exception:
        return str(name)


async def fetch_certificates_for_hosts(
    hostnames: List[str], validator: ScopeValidator
) -> Dict[str, CertificateInfo]:
    results: Dict[str, CertificateInfo] = {}
    for host in hostnames:
        results[host] = await fetch_certificate(host, validator)
    return results
