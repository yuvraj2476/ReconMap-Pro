"""Scope-enforcing async HTTP client.

This is the ONLY place outbound HTTP requests are constructed. It validates
scope, blocks unsafe IPs (SSRF), applies a polite rate limit, sets a
transparent User-Agent, and validates every redirect hop stays in scope.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.config import Settings
from app.security.ratelimiter import InMemoryRateLimiter
from app.security.scope import ScopeValidator

logger = logging.getLogger(__name__)


@dataclass
class FetchResult:
    url: str
    status_code: int
    headers: dict
    text: str
    content: bytes
    elapsed_ms: float
    final_url: str
    ip: Optional[str] = None


class SafeHttpClient:
    """An httpx client that refuses out-of-scope or SSRF targets."""

    def __init__(
        self,
        validator: ScopeValidator,
        settings: Settings,
        rate_limiter: Optional[InMemoryRateLimiter] = None,
    ) -> None:
        self.validator = validator
        self.settings = settings
        self.rate_limiter = rate_limiter or InMemoryRateLimiter(
            rate_per_sec=max(1.0, settings.max_concurrent_requests / 2),
            burst=settings.max_concurrent_requests,
        )
        self._client = httpx.AsyncClient(
            timeout=settings.request_timeout,
            follow_redirects=False,  # we validate each hop ourselves
            verify=True,
            headers={"User-Agent": settings.user_agent, "Accept": "*/*"},
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "SafeHttpClient":
        return self

    async def __aexit__(self, *exc) -> None:
        await self.aclose()

    async def get(self, url: str, *, allow_redirects: bool = True) -> Optional[FetchResult]:
        """Fetch a URL, validating scope and SSRF at every hop."""
        current = url
        hops = 0
        max_hops = self.settings.max_redirects if allow_redirects else 0
        last_result: Optional[FetchResult] = None

        while True:
            # 1. Validate scope + resolve IP + block private/metadata
            try:
                host, _, ips = await self.validator.validate_url(current)
            except Exception as exc:
                logger.warning("Blocked request to %s: %s", current, exc)
                return None

            await self.rate_limiter.acquire(host)
            start = time.perf_counter()
            target_url = current
            req_headers = {}

            parsed_current = urlparse(current)
            if ips and (self.validator.allow_private_networks or host.endswith(".local") or host == "localhost"):
                target_ip = ips[0]
                port_str = f":{parsed_current.port}" if parsed_current.port else ""
                req_headers["Host"] = parsed_current.netloc or host
                target_netloc = f"{target_ip}{port_str}" if ":" not in target_ip else f"[{target_ip}]{port_str}"
                target_url = parsed_current._replace(netloc=target_netloc).geturl()

            try:
                resp = await self._client.get(target_url, headers=req_headers if req_headers else None)
            except (httpx.HTTPError, Exception) as exc:
                logger.debug("HTTP error fetching %s: %s", current, exc)
                return None
            elapsed = (time.perf_counter() - start) * 1000.0

            last_result = FetchResult(
                url=url,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                text=resp.text,
                content=resp.content,
                elapsed_ms=elapsed,
                final_url=current,
                ip=ips[0] if ips else None,
            )

            if resp.is_redirect and allow_redirects and hops < max_hops:
                location = resp.headers.get("location", "")
                if not location:
                    return last_result
                current = urljoin(str(resp.url), location)
                hops += 1
                continue
            return last_result

    async def get_text(self, url: str) -> Optional[str]:
        result = await self.get(url)
        return result.text if result else None
