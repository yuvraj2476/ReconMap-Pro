"""Subdomain discovery.

Passive sources:
  * Certificate Transparency logs via crt.sh (public, unauthenticated JSON API)
  * DNS zone records already enumerated (NS/MX/CNAME targets that stay in scope)

Optional active source (off by default, tightly constrained):
  * A small built-in wordlist with strict rate limiting. Bruteforce-style
    enumeration is NOT a feature; the wordlist is intentionally tiny and only
    used when the operator explicitly opts in. We never attempt credential
    attacks or dictionary attacks against services.
"""
from __future__ import annotations

import asyncio
import logging
from typing import List, Set

import httpx

from app.config import Settings
from app.recon.http_client import SafeHttpClient
from app.security.scope import ScopeValidator
from app.recon.binary_downloader import download_subfinder
from app.recon.provider_config import generate_subfinder_config

logger = logging.getLogger(__name__)

# Tiny, conservative wordlist for the optional active check. This is NOT a
# bruteforce list; it covers common infrastructure labels and is rate-limited.
_MINI_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "ftp", "localhost", "m", "shop", "api", "dev", "staging",
    "test", "portal", "vpn", "cdn", "admin", "img", "static", "assets",
    "docs", "support", "app", "git", "ci", "jenkins", "grafana", "kibana",
    "status", "help", "wiki", "go", "news", "download", "store", "secure",
    "dashboard", "auth", "id", "sso", "build", "repo", "registry",
]

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


async def discover_from_crtsh(domain: str, *, timeout: float = 15.0) -> List[str]:
    """Query certificate transparency logs via crt.sh."""
    found: Set[str] = set()
    url = CRT_SH_URL.format(domain=domain)
    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.info("crt.sh query failed for %s: %s", domain, exc)
            return []

    for entry in data:
        for field_name in ("name_value", "common_name"):
            value = entry.get(field_name)
            if not value:
                continue
            for line in value.splitlines():
                name = line.strip().lower().lstrip("*.")
                if name and name.endswith(domain):
                    found.add(name)
    return sorted(found)


async def discover_from_dns(subdomains: List[str], validator: ScopeValidator) -> List[str]:
    """Resolve candidate subdomains; return those that exist and are in scope."""
    valid: List[str] = []

    async def _check(name: str) -> None:
        try:
            validator.assert_in_scope(name)
        except Exception:
            return
        ips = await validator.resolve(name)
        if ips:
            valid.append(name)

    # Small, bounded concurrency - keep it polite.
    sem = asyncio.Semaphore(8)

    async def _guarded(name: str) -> None:
        async with sem:
            await _check(name)

    await asyncio.gather(*(_guarded(s) for s in subdomains))
    return valid


async def discover_subdomains(
    domain: str,
    validator: ScopeValidator,
    settings: Settings,
    *,
    enable_active: bool = False,
) -> List[str]:
    """Return a de-duplicated list of discovered in-scope subdomains."""
    root = validator.assert_in_scope(domain)
    candidates: Set[str] = {root}

    # 1. Passive: certificate transparency
    passive = await discover_from_crtsh(root)
    for name in passive:
        if validator.is_in_scope(name):
            candidates.add(name)

    # 1b. Advanced Subdomain Enumeration: Subfinder
    binary_path = await download_subfinder(settings.allow_tool_download)
    if binary_path:
        config_path = generate_subfinder_config(settings)
        logger.info("Running advanced subdomain enumeration with subfinder on %s", root)
        try:
            proc = await asyncio.create_subprocess_exec(
                binary_path, "-d", root, "-pc", config_path, "-silent",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                for line in stdout.decode().splitlines():
                    name = line.strip().lower()
                    if name and validator.is_in_scope(name):
                        candidates.add(name)
            else:
                logger.error("subfinder execution failed with code %d: %s", proc.returncode, stderr.decode())
        except Exception as exc:
            logger.error("Failed to run subfinder subprocess: %s", exc)

    # 2. Optional active: constrained wordlist (NOT bruteforce)
    if enable_active and not settings.passive_only:
        wordlist = _MINI_WORDLIST[: settings.subdomain_wordlist_size]
        checks = [f"{w}.{root}" for w in wordlist]
        active = await discover_from_dns(checks, validator)
        candidates.update(active)

    # 3. Final resolution filter for everything not yet confirmed
    confirmed = await discover_from_dns(sorted(candidates), validator)
    # Keep the root even if it doesn't resolve (it's the scan target).
    confirmed_set = set(confirmed)
    confirmed_set.add(root)
    return sorted(confirmed_set)
