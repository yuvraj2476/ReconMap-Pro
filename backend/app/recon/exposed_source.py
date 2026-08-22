"""Exposed codebase and backup files scanner."""
from __future__ import annotations

import logging
from typing import List, Optional
from urllib.parse import urljoin

from app.recon.http_client import SafeHttpClient
from app.security.scope import ScopeValidator

logger = logging.getLogger(__name__)

def _format_size(size_bytes: int) -> str:
    """Format size into a human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"

async def check_exposed_code(
    base_url: str, client: SafeHttpClient, validator: ScopeValidator
) -> List[dict]:
    """Scan the given base URL for exposed codebase repositories or zip backups.

    Returns:
        List of dict, each representing an exposed codebase target found.
    """
    found = []
    
    # Define candidates to check: path, type description, verification check
    candidates = [
        {
            "path": ".git/config",
            "type": "Git Repository",
            "check": lambda text, content: "[core]" in text or "repositoryformatversion" in text
        },
        {
            "path": ".git/HEAD",
            "type": "Git Repository",
            "check": lambda text, content: text.startswith("ref:") or len(text.strip()) == 40
        },
        {
            "path": "backup.zip",
            "type": "Zip Backup",
            "check": lambda text, content: content.startswith(b"PK\x03\x04") or len(content) > 10000
        },
        {
            "path": "code.zip",
            "type": "Zip Backup",
            "check": lambda text, content: content.startswith(b"PK\x03\x04") or len(content) > 10000
        },
        {
            "path": "project.zip",
            "type": "Zip Backup",
            "check": lambda text, content: content.startswith(b"PK\x03\x04") or len(content) > 10000
        },
        {
            "path": "src.zip",
            "type": "Zip Backup",
            "check": lambda text, content: content.startswith(b"PK\x03\x04") or len(content) > 10000
        }
    ]

    for cand in candidates:
        target_url = urljoin(base_url, cand["path"])
        # Validate scope for the full target url
        try:
            await validator.validate_url(target_url)
        except Exception:
            continue

        try:
            result = await client.get(target_url, allow_redirects=False)
            if not result or result.status_code != 200:
                continue

            # Verify it matches the content signature to avoid false positives (e.g. custom 404 pages returning 200)
            if not cand["check"](result.text, result.content):
                continue

            # Resolve estimated size from Content-Length header or length of content
            cl = result.headers.get("content-length")
            size_bytes = int(cl) if cl and cl.isdigit() else len(result.content)

            found.append({
                "url": target_url,
                "code_type": cand["type"],
                "size_bytes": size_bytes,
                "size_human": _format_size(size_bytes),
                "path": cand["path"]
            })
            logger.info("Found exposed %s codebase at %s (size: %s)", cand["type"], target_url, _format_size(size_bytes))
        except Exception as exc:
            logger.debug("Error probing exposed code candidate %s: %s", target_url, exc)

    return found
