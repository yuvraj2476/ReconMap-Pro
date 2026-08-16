"""Asset attention / prioritization scoring.

Each asset receives a 0-100 "attention score" indicating how strongly a
security reviewer should focus on it. The score is heuristic and transparent:
it rewards exposure (public IP, no WAF), sensitive technology (admin panels,
old versions, debug mode), missing security headers, and leaked secrets.
"""
from __future__ import annotations

from typing import Dict, Iterable, List

from app.models import Asset, AssetType, Observation, Severity

# Weights for asset types (how interesting they are by default).
TYPE_WEIGHT: Dict[AssetType, int] = {
    AssetType.API: 55,
    AssetType.URL: 35,
    AssetType.SUBDOMAIN: 30,
    AssetType.IP: 40,
    AssetType.JAVASCRIPT: 25,
    AssetType.TECHNOLOGY: 15,
    AssetType.CERTIFICATE: 15,
    AssetType.DOMAIN: 10,
    AssetType.ASN: 5,
    AssetType.ORGANIZATION: 5,
    AssetType.DNS_RECORD: 10,
    AssetType.HOSTING: 5,
    AssetType.WEB_SERVER: 20,
}

SEVERITY_BONUS: Dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 8,
    Severity.MEDIUM: 20,
    Severity.HIGH: 40,
}

SENSITIVE_KEYWORDS = [
    "admin", "dashboard", "console", "phpmyadmin", "jenkins", "grafana",
    "kibana", "swagger", "api-docs", "debug", "test", "staging", "dev",
    "backup", "old", "vpn", "git", "registry", "actuator",
]


def score_asset(asset: Asset, observations: Iterable[Observation] = ()) -> int:
    score = TYPE_WEIGHT.get(asset.type, 10)
    props = asset.properties or {}
    name = (asset.name or "").lower()

    # Sensitive keywords in the name
    for kw in SENSITIVE_KEYWORDS:
        if kw in name:
            score += 12
            break

    # HTTP/HTTPS status signals
    if asset.type in (AssetType.URL, AssetType.API):
        status = props.get("status_code")
        if isinstance(status, int):
            if status >= 500:
                score += 15
            elif status >= 400:
                score += 6
            elif status in (401, 403):
                score += 8
        if props.get("is_api"):
            score += 10
        if props.get("scheme") == "http":
            score += 12  # plaintext
        missing = props.get("missing_security_headers") or []
        score += min(len(missing) * 3, 18)

    # Subdomain signals
    if asset.type == AssetType.SUBDOMAIN:
        if props.get("is_wildcard"):
            score += 8
        if props.get("has_https") is False:
            score += 10

    # Certificate signals
    if asset.type == AssetType.CERTIFICATE:
        if props.get("expired"):
            score += 35
        if props.get("expires_soon"):
            score += 20
        if props.get("self_signed") or props.get("verify_error"):
            score += 20
        if props.get("san_count", 0) > 20:
            score += 8

    # JavaScript signals
    if asset.type == AssetType.JAVASCRIPT:
        if props.get("secret_count", 0) > 0:
            score += 40
        if props.get("source_map"):
            score += 10
        if props.get("endpoint_count", 0) > 5:
            score += 10

    # Technology signals
    if asset.type == AssetType.TECHNOLOGY:
        if props.get("version_outdated"):
            score += 15
        if props.get("category") in ("Web Server", "CMS", "Web Framework"):
            score += 5

    # Observations attached to this asset
    for obs in observations:
        score += SEVERITY_BONUS.get(obs.severity, 0)

    return int(max(0, min(100, score)))


def score_assets(assets: List[Asset], observations: List[Observation]) -> List[Asset]:
    by_asset: Dict[str, List[Observation]] = {}
    for obs in observations:
        if obs.asset_id:
            by_asset.setdefault(obs.asset_id, []).append(obs)
    for asset in assets:
        asset.attention_score = score_asset(asset, by_asset.get(asset.id, []))
    return assets
