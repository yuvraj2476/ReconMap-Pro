"""IP, ASN, hosting and cloud attribution.

Uses passive sources:
  * RDAP (Registration Data Access Protocol) for IP -> network/org attribution
  * Team Cymru's DNS-based ASN service (whois.cymru.com over TXT records)
  * Static cloud CIDR signatures for major providers

No port scanning is performed; attribution is metadata-only.
"""
from __future__ import annotations

import ipaddress
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import dns.asyncresolver
import httpx

from app.security.scope import _is_blocked_ip  # noqa: PLC2701

logger = logging.getLogger(__name__)

CLOUD_SIGNATURES = {
    "Amazon AWS": [
        "3.0.0.0/8", "13.32.0.0/15", "15.177.0.0/18", "15.230.0.0/16",
        "18.32.0.0/11", "34.192.0.0/10", "35.152.0.0/15", "52.0.0.0/11",
        "54.64.0.0/11", "99.77.0.0/16",
    ],
    "Google Cloud": [
        "34.64.0.0/10", "35.184.0.0/13", "35.192.0.0/14", "35.196.0.0/15",
        "35.198.0.0/16", "35.199.0.0/17", "35.200.0.0/13", "35.208.0.0/12",
        "35.224.0.0/12", "35.240.0.0/13", "104.196.0.0/14", "130.211.0.0/16",
        "146.148.0.0/17",
    ],
    "Microsoft Azure": [
        "13.64.0.0/11", "20.0.0.0/8", "40.64.0.0/10", "52.224.0.0/11",
        "104.40.0.0/13", "137.116.0.0/15", "168.61.0.0/16",
    ],
    "Cloudflare": [
        "104.16.0.0/12", "172.64.0.0/13",
    ],
    "DigitalOcean": [
        "104.131.0.0/16", "138.68.0.0/16", "138.197.0.0/16", "139.59.0.0/16",
        "157.230.0.0/16", "159.65.0.0/16", "159.89.0.0/16", "165.227.0.0/16",
        "167.99.0.0/16", "206.189.0.0/16",
    ],
    "Linode / Akamai": [
        "45.33.0.0/16", "45.56.0.0/16", "45.79.0.0/16", "50.116.0.0/16",
        "66.175.208.0/20", "72.14.176.0/20", "96.126.96.0/19", "173.255.192.0/18",
        "198.58.96.0/19",
    ],
    "Vultr": [
        "45.32.0.0/16", "45.63.0.0/16", "45.76.0.0/16", "66.42.32.0/19",
        "95.179.128.0/18", "104.156.224.0/19", "108.61.0.0/16", "136.244.64.0/18",
        "140.82.0.0/18", "149.28.0.0/16", "155.138.112.0/20", "167.71.0.0/16",
        "192.248.144.0/20", "199.27.72.0/21", "207.148.0.0/16", "216.128.128.0/18",
    ],
    "Hetzner": [
        "46.4.0.0/16", "49.12.0.0/16", "78.46.0.0/15", "88.198.0.0/16",
        "116.202.0.0/16", "128.140.0.0/16", "136.243.0.0/16", "138.201.0.0/16",
        "144.76.0.0/16", "148.251.0.0/16", "159.69.0.0/16", "162.55.0.0/16",
        "176.9.0.0/16", "178.63.0.0/16", "188.40.0.0/16", "195.201.0.0/16",
    ],
    "OVH": [
        "37.59.0.0/16", "46.105.0.0/16", "51.254.0.0/16", "79.137.0.0/16",
        "87.98.0.0/16", "91.121.0.0/16", "92.222.0.0/16", "94.23.0.0/16",
        "109.190.0.0/16", "151.80.0.0/16", "158.69.0.0/16", "167.114.0.0/16",
        "176.31.0.0/16", "188.165.0.0/16", "192.95.0.0/18", "198.27.64.0/18",
        "198.50.128.0/17", "198.100.144.0/20", "199.247.0.0/16",
    ],
    "Oracle Cloud": [
        "129.146.0.0/16", "130.61.0.0/16", "132.145.0.0/16", "134.70.0.0/16",
        "140.238.0.0/16", "147.154.0.0/16", "150.136.0.0/16", "152.67.0.0/16",
        "155.248.0.0/16", "158.101.0.0/16", "168.138.0.0/16", "192.9.168.0/24",
        "193.122.48.0/20", "195.130.40.0/21", "198.58.112.0/20",
    ],
}

_NETWORKS = {
    provider: [ipaddress.ip_network(cidr) for cidr in cidrs]
    for provider, cidrs in CLOUD_SIGNATURES.items()
}


@dataclass
class IpInfo:
    ip: str
    asn: Optional[str] = None
    org: Optional[str] = None
    isp: Optional[str] = None
    country: Optional[str] = None
    network_name: Optional[str] = None
    cidr: Optional[str] = None
    cloud_provider: Optional[str] = None
    is_private: bool = False
    reverse_dns: Optional[str] = None
    rdap: dict = field(default_factory=dict)


def _detect_cloud(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for provider, nets in _NETWORKS.items():
        for net in nets:
            if addr in net:
                return provider
    return None


async def _cymru_asn(ip: str, resolver: dns.asyncresolver.Resolver) -> Optional[str]:
    """Use Team Cymru DNS ASN service: <rev>.origin.asn.cymru.com TXT."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        rev = ".".join(reversed(ip.split(".")))
        query = f"{rev}.origin.asn.cymru.com"
    else:
        rev = ".".join(reversed(addr.exploded.replace(":", "")))
        query = f"{rev}.origin6.asn.cymru.com"
    try:
        answers = await resolver.resolve(query, "TXT")
        for r in answers:
            txt = "".join(s.decode("utf-8", "replace") for s in r.strings)
            parts = txt.split("|")
            if parts:
                return parts[0].strip()
    except Exception:
        return None
    return None


async def _rdap(ip: str) -> dict:
    """Query RDAP for network information."""
    url = f"https://rdap.org/ip/{ip}"
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.json()
    except Exception as exc:
        logger.debug("RDAP lookup failed for %s: %s", ip, exc)
    return {}


def _parse_rdap(rdap: dict) -> dict:
    out: dict = {}
    if not rdap:
        return out
    out["network_name"] = rdap.get("name")
    out["country"] = rdap.get("country")
    out["cidr"] = None
    for cidr in rdap.get("cidr0_cidrs", []):
        out["cidr"] = f"{cidr.get('v4prefix') or cidr.get('v6prefix')}/{cidr.get('length')}"
        break
    entities = rdap.get("entities", [])
    for ent in entities:
        vcard = ent.get("vcardArray", [])
        if len(vcard) > 1 and isinstance(vcard[1], list):
            for item in vcard[1]:
                if item[0] == "fn":
                    out.setdefault("org", item[3])
    # Handle nested entities
    for ent in entities:
        for sub in ent.get("entities", []):
            vcard = sub.get("vcardArray", [])
            if len(vcard) > 1 and isinstance(vcard[1], list):
                for item in vcard[1]:
                    if item[0] == "fn":
                        out.setdefault("org", item[3])
    return out


async def lookup_ip(ip: str, resolver: Optional[dns.asyncresolver.Resolver] = None) -> IpInfo:
    """Look up ASN/org/cloud attribution for an IP."""
    resolver = resolver or dns.asyncresolver.Resolver()
    info = IpInfo(ip=ip)

    try:
        addr = ipaddress.ip_address(ip)
        info.is_private = addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return info

    # Cloud detection is immediate and free
    info.cloud_provider = _detect_cloud(ip)

    if info.is_private:
        info.org = "Private Network"
        return info

    # RDAP (network/org)
    rdap = await _rdap(ip)
    parsed = _parse_rdap(rdap)
    info.rdap = rdap
    info.network_name = parsed.get("network_name")
    info.country = parsed.get("country")
    info.cidr = parsed.get("cidr")
    info.org = parsed.get("org")

    # ASN via Cymru
    info.asn = await _cymru_asn(ip, resolver)

    # Reverse DNS
    try:
        answers = await resolver.resolve_address(ip)
        if answers:
            info.reverse_dns = str(answers[0]).rstrip(".")
    except Exception:
        pass

    return info


async def lookup_ips(ips: List[str], resolver=None) -> Dict[str, IpInfo]:
    """Bulk lookup; de-duplicates IPs."""
    unique = sorted(set(ips))
    results: Dict[str, IpInfo] = {}
    for ip in unique:
        results[ip] = await lookup_ip(ip, resolver)
    return results
