"""Static JavaScript asset analysis.

Downloads in-scope JavaScript files (through the scope-enforcing HTTP client)
and extracts:
  * Absolute/relative URLs and path-like strings
  * Likely API endpoints (/api/..., /v1/..., etc.)
  * Hardcoded secrets indicators (entropy + key patterns) - reported as
    observations; never exploited.
  * Source map references
  * Comments containing author/license information
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Set
from urllib.parse import urljoin

from app.recon.http_client import SafeHttpClient
from app.security.scope import ScopeValidator

logger = logging.getLogger(__name__)

URL_RE = re.compile(
    r"""(?xi)
    \b(?:
        https?://[a-z0-9\-.]+(?:\:[0-9]+)?(?:/[^\s"'`<>\\]*)?
      | /[a-z0-9_\-/.]+(?:\?[^\s"'`<>\\]*)?
    )\b
    """
)
API_PATH_RE = re.compile(
    r"""(?xi)
    (?<!\w)/(?:api|rest|graphql|v\d+(?:\.\d+)?|service|services|internal|public)/
    [a-z0-9_\-/.]+
    """,
    re.IGNORECASE,
)
SECRET_PATTERNS = {
    "AWS Access Key ID": re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "AWS Secret Access Key": re.compile(r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "GitHub Token": re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    "Slack Token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    "Stripe Key": re.compile(r"\b(?:sk|pk)_(?:live|test)_[0-9a-zA-Z]{24,}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    "Private Key": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
}
SOURCE_MAP_RE = re.compile(r"//# sourceMappingURL=([^\s]+)")


@dataclass
class JsAnalysis:
    url: str
    size: int = 0
    endpoints: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    secrets: List[dict] = field(default_factory=list)
    source_map: Optional[str] = None
    fetchable: bool = True
    error: Optional[str] = None


def _shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


async def analyze_js(
    url: str, client: SafeHttpClient, validator: ScopeValidator
) -> JsAnalysis:
    analysis = JsAnalysis(url=url)
    result = await client.get(url)
    if not result:
        analysis.fetchable = False
        analysis.error = "unreachable"
        return analysis

    text = result.text or ""
    analysis.size = len(result.content)

    # URLs and paths
    found_urls: Set[str] = set()
    for m in URL_RE.finditer(text):
        candidate = m.group(0).rstrip(".,;")
        if candidate.startswith("http"):
            found_urls.add(candidate)
        else:
            found_urls.add(urljoin(result.final_url, candidate))
    analysis.urls = sorted(found_urls)

    # API endpoints
    endpoints: Set[str] = set()
    for m in API_PATH_RE.finditer(text):
        endpoints.add(m.group(0))
    for u in found_urls:
        if API_PATH_RE.search(u):
            endpoints.add(u)
    analysis.endpoints = sorted(endpoints)

    # Secrets
    for label, pattern in SECRET_PATTERNS.items():
        for m in pattern.finditer(text):
            match_text = m.group(0)
            entropy = _shannon_entropy(match_text)
            # Only report high-entropy matches to reduce false positives.
            if entropy > 3.0 or label in ("Private Key", "JWT"):
                analysis.secrets.append({
                    "type": label,
                    "preview": match_text[:12] + "..." + match_text[-4:],
                    "entropy": round(entropy, 2),
                })

    # Source map
    sm = SOURCE_MAP_RE.search(text)
    if sm:
        analysis.source_map = urljoin(result.final_url, sm.group(1))

    return analysis


async def analyze_js_bundle(
    urls: List[str], client: SafeHttpClient, validator: ScopeValidator
) -> List[JsAnalysis]:
    results: List[JsAnalysis] = []
    for u in urls:
        results.append(await analyze_js(u, client, validator))
    return results
