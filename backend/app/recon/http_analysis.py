"""HTTP/HTTPS analysis and security-header observations."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from app.recon.http_client import FetchResult, SafeHttpClient
from app.recon.tech import TechMatch, fingerprint
from app.security.scope import ScopeValidator


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
}

INFORMATIONAL_HEADERS = [
    "server", "x-powered-by", "x-aspnet-version", "x-generator",
    "via", "x-served-by", "x-cache", "x-amz-cf-id", "cf-ray",
]


@dataclass
class HttpAnalysis:
    url: str
    final_url: str
    status_code: int
    scheme: str
    host: str
    ip: Optional[str] = None
    server: Optional[str] = None
    powered_by: Optional[str] = None
    content_type: Optional[str] = None
    content_length: Optional[int] = None
    title: Optional[str] = None
    elapsed_ms: float = 0.0
    redirect_chain: List[str] = field(default_factory=list)
    security_headers_present: List[str] = field(default_factory=list)
    security_headers_missing: List[str] = field(default_factory=list)
    cookies: List[dict] = field(default_factory=list)
    technologies: List[TechMatch] = field(default_factory=list)
    headers: dict = field(default_factory=dict)
    reachable: bool = False
    error: Optional[str] = None


def _extract_title(html: str) -> Optional[str]:
    if not html:
        return None
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()[:200]
    return None


def _parse_cookies(set_cookie: str) -> List[dict]:
    out = []
    for chunk in set_cookie.split(","):
        part = chunk.split(";")[0].strip()
        if "=" in part:
            name, _, value = part.partition("=")
            flags = {}
            for seg in chunk.split(";")[1:]:
                seg = seg.strip().lower()
                if "=" in seg:
                    k, _, v = seg.partition("=")
                    flags[k.strip()] = v.strip()
                else:
                    flags[seg] = True
            out.append({"name": name.strip(), "secure": flags.get("secure", False),
                        "httponly": flags.get("httponly", False),
                        "samesite": flags.get("samesite")})
    return out


async def analyze_http(
    url: str, client: SafeHttpClient, validator: ScopeValidator
) -> HttpAnalysis:
    """Fetch and analyse a URL. Returns a structured result."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    analysis = HttpAnalysis(
        url=url, final_url=url, status_code=0, scheme=parsed.scheme, host=parsed.hostname or ""
    )

    result: Optional[FetchResult] = await client.get(url)
    if not result:
        analysis.error = "unreachable"
        return analysis

    analysis.reachable = True
    analysis.status_code = result.status_code
    analysis.final_url = result.final_url
    analysis.elapsed_ms = result.elapsed_ms
    analysis.ip = result.ip
    analysis.headers = {k.lower(): v for k, v in result.headers.items()}
    analysis.server = analysis.headers.get("server")
    analysis.powered_by = analysis.headers.get("x-powered-by")
    analysis.content_type = analysis.headers.get("content-type", "").split(";")[0]
    cl = analysis.headers.get("content-length")
    analysis.content_length = int(cl) if cl and cl.isdigit() else len(result.content)
    analysis.title = _extract_title(result.text)

    # Security headers
    for header in SECURITY_HEADERS:
        if header in analysis.headers:
            analysis.security_headers_present.append(header)
        else:
            analysis.security_headers_missing.append(header)

    # Cookies
    set_cookie = result.headers.get("set-cookie", "")
    if set_cookie:
        analysis.cookies = _parse_cookies(set_cookie)

    # Fingerprinting
    analysis.technologies = fingerprint(result)
    return analysis
