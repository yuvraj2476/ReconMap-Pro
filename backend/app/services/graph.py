"""Build the attack-surface graph from assets and relations.

Produces a Cytoscape.js-compatible node/edge structure. Every edge carries
source, timestamp, confidence and evidence.
"""
from __future__ import annotations

from typing import Dict, List

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Asset, Relation, RelationType

# Visual styling hints per asset type (consumed by the frontend).
NODE_STYLES = {
    "domain":        {"color": "#60a5fa", "icon": "globe"},
    "subdomain":     {"color": "#38bdf8", "icon": "branch"},
    "ip":            {"color": "#a78bfa", "icon": "server"},
    "asn":           {"color": "#c084fc", "icon": "network"},
    "organization":  {"color": "#e879f9", "icon": "building"},
    "certificate":   {"color": "#fbbf24", "icon": "shield"},
    "technology":    {"color": "#34d399", "icon": "puzzle"},
    "url":           {"color": "#94a3b8", "icon": "link"},
    "api":           {"color": "#fb923c", "icon": "plug"},
    "javascript":    {"color": "#facc15", "icon": "code"},
    "dns_record":    {"color": "#22d3ee", "icon": "dns"},
    "hosting":       {"color": "#2dd4bf", "icon": "cloud"},
    "web_server":    {"color": "#f472b6", "icon": "server"},
}

RELATION_LABELS = {
    RelationType.HAS_SUBDOMAIN.value: "has subdomain",
    RelationType.RESOLVES_TO.value: "resolves to",
    RelationType.ANNOUNCED_BY.value: "announced by",
    RelationType.OWNED_BY.value: "owned by",
    RelationType.PRESENTS.value: "presents",
    RelationType.USES.value: "uses",
    RelationType.HOSTED_BY.value: "hosted by",
    RelationType.SERVED_BY.value: "served by",
    RelationType.LINKS_TO.value: "links to",
    RelationType.EXPOSES.value: "exposes",
    RelationType.REFERENCES.value: "references",
    RelationType.HAS_DNS.value: "has record",
}


async def build_graph(db: AsyncSession, scan_id: str) -> dict:
    assets = (await db.execute(
        select(Asset).where(Asset.scan_id == scan_id).order_by(Asset.type, Asset.name)
    )).scalars().all()
    relations = (await db.execute(
        select(Relation).where(Relation.scan_id == scan_id)
    )).scalars().all()

    asset_by_id: Dict[str, Asset] = {a.id: a for a in assets}

    nodes = []
    for a in assets:
        style = NODE_STYLES.get(a.type.value, {"color": "#94a3b8", "icon": "circle"})
        nodes.append({
            "data": {
                "id": a.id,
                "label": a.name,
                "type": a.type.value,
                "color": style["color"],
                "icon": style["icon"],
                "score": a.attention_score,
                "confidence": a.confidence,
                "source": a.source,
                "properties": a.properties,
            }
        })

    edges = []
    for r in relations:
        if r.source_id not in asset_by_id or r.target_id not in asset_by_id:
            continue
        edges.append({
            "data": {
                "id": r.id,
                "source": r.source_id,
                "target": r.target_id,
                "label": RELATION_LABELS.get(r.type.value, r.type.value),
                "type": r.type.value,
                "confidence": r.confidence,
                "source_module": r.source,
                "evidence": r.evidence,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
            }
        })

    return {"nodes": nodes, "edges": edges}
