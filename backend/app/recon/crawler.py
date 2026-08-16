"""Scope-aware web crawler.

The crawler is intentionally polite:
  * It only follows links that stay inside the authorized scope.
  * It honours a depth cap, a page cap and a concurrency cap.
  * It parses HTML with BeautifulSoup and extracts links, forms, scripts,
    stylesheets and images, but it NEVER submits forms or performs state-
    changing requests.
  * It classifies discovered URLs and flags likely public API endpoints.
"""
from __future__ import annotations

import asyncio
import logging
import re
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urldefrag, urljoin, urlparse

from bs4 import BeautifulSoup

from app.config import Settings
from app.recon.http_client import FetchResult, SafeHttpClient
from app.security.scope import ScopeValidator

logger = logging.getLogger(__name__)

API_HINT_PATTERNS = [
    re.compile(r"/api/", re.IGNORECASE),
    re.compile(r"/v\d+/", re.IGNORECASE),
    re.compile(r"/graphql", re.IGNORECASE),
    re.compile(r"/rest/", re.IGNORECASE),
    re.compile(r"\.(json|xml|yaml)(?:\?|$)", re.IGNORECASE),
    re.compile(r"/swagger", re.IGNORECASE),
    re.compile(r"/openapi", re.IGNORECASE),
    re.compile(r"/healthz|/readyz|/metrics", re.IGNORECASE),
]

INTERESTING_EXT = {
    ".js", ".json", ".xml", ".yaml", ".yml", ".map", ".env", ".bak",
    ".sql", ".log", ".php", ".asp", ".aspx", ".jsp", ".do", ".action",
}
ASSET_EXT = {".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".webp"}


@dataclass
class CrawledUrl:
    url: str
    status_code: int
    depth: int
    content_type: str
    title: Optional[str] = None
    is_api: bool = False
    is_javascript: bool = False
    is_asset: bool = False
    links_out: List[str] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    forms: List[dict] = field(default_factory=list)
    error: Optional[str] = None


@dataclass
class CrawlResult:
    start_url: str
    pages: List[CrawledUrl] = field(default_factory=list)
    js_assets: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    external_links: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _classify(url: str, content_type: str) -> Dict[str, bool]:
    path = urlparse(url).path.lower()
    is_js = "javascript" in content_type or path.endswith(".js")
    is_asset = any(path.endswith(ext) for ext in ASSET_EXT)
    is_api = any(p.search(url) for p in API_HINT_PATTERNS)
    if "json" in content_type and not is_api:
        is_api = True
    return {"is_api": is_api, "is_javascript": is_js, "is_asset": is_asset}


def _looks_like_api(url: str, method: str = "GET", content_type: str = "") -> bool:
    return _classify(url, content_type)["is_api"]


async def crawl(
    start_url: str,
    client: SafeHttpClient,
    validator: ScopeValidator,
    settings: Settings,
    *,
    max_depth: Optional[int] = None,
    max_pages: Optional[int] = None,
) -> CrawlResult:
    """Breadth-first crawl within the authorized scope."""
    max_depth = max_depth if max_depth is not None else settings.max_crawl_depth
    max_pages = max_pages if max_pages is not None else settings.max_crawl_pages
    result = CrawlResult(start_url=start_url)

    parsed_start = urlparse(start_url)
    start_host = parsed_start.hostname or ""
    # Scope must already contain the host; this re-validates.
    host, _, _ = await validator.validate_url(start_url)

    queue: deque = deque([(start_url, 0)])
    visited: Set[str] = set()
    js_assets: Set[str] = set()
    api_endpoints: Set[str] = set()
    external: Set[str] = set()
    sem = asyncio.Semaphore(settings.max_concurrent_requests)

    async def _fetch(url: str, depth: int) -> Optional[CrawledUrl]:
        page = CrawledUrl(url=url, status_code=0, depth=depth, content_type="")
        try:
            fetch: Optional[FetchResult] = await client.get(url)
        except Exception as exc:  # pragma: no cover
            page.error = str(exc)
            result.errors.append(f"{url}: {exc}")
            return page
        if not fetch:
            page.error = "unreachable"
            result.errors.append(f"{url}: unreachable")
            return page

        page.status_code = fetch.status_code
        page.content_type = fetch.headers.get("content-type", "").split(";")[0]
        classification = _classify(url, page.content_type)
        page.is_api = classification["is_api"]
        page.is_javascript = classification["is_javascript"]
        page.is_asset = classification["is_asset"]

        if page.is_api:
            api_endpoints.add(url)
        if page.is_javascript:
            js_assets.add(url)
            # Don't parse JS as HTML
            return page
        if page.is_asset:
            return page

        # Parse HTML for links
        if "html" in page.content_type and fetch.text:
            soup = BeautifulSoup(fetch.text, "lxml")
            title = soup.find("title")
            page.title = title.get_text(strip=True)[:200] if title else None

            links: Set[str] = set()
            for a in soup.find_all("a", href=True):
                links.add(urljoin(fetch.final_url, a["href"]))
            for link in soup.find_all(["link", "area"], href=True):
                links.add(urljoin(fetch.final_url, link["href"]))
            for form in soup.find_all("form", action=True):
                action = urljoin(fetch.final_url, form["action"])
                method = (form.get("method") or "get").upper()
                page.forms.append({
                    "action": action, "method": method,
                    "enctype": form.get("enctype", ""),
                })
                if method != "GET":
                    # We do NOT submit non-GET forms. Record for awareness only.
                    logger.debug("Not submitting %s form to %s (out of policy)", method, action)
                links.add(action)

            for script in soup.find_all("script", src=True):
                src = urljoin(fetch.final_url, script["src"])
                page.scripts.append(src)
                js_assets.add(src)

            for link in links:
                link, _ = urldefrag(link)
                if not link or not link.startswith(("http://", "https://")):
                    continue
                link_host = urlparse(link).hostname or ""
                if validator.is_in_scope(link_host):
                    page.links_out.append(link)
                else:
                    external.add(link)
        return page

    while queue and len(result.pages) < max_pages:
        batch: List[tuple] = []
        while queue and len(batch) < settings.max_concurrent_requests:
            url, depth = queue.popleft()
            norm = urldefrag(url)[0]
            if norm in visited or depth > max_depth:
                continue
            visited.add(norm)
            batch.append((norm, depth))
        if not batch:
            break

        async def _guarded(u: str, d: int) -> Optional[CrawledUrl]:
            async with sem:
                return await _fetch(u, d)

        pages = await asyncio.gather(*[_guarded(u, d) for u, d in batch])
        for page in pages:
            if page is None:
                continue
            result.pages.append(page)
            if page.error:
                continue
            for link in page.links_out:
                norm = urldefrag(link)[0]
                if norm not in visited:
                    queue.append((norm, page.depth + 1))

    result.js_assets = sorted(js_assets)
    result.api_endpoints = sorted(api_endpoints)
    result.external_links = sorted(external)
    return result
