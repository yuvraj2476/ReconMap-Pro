"""Historical scan comparison: new, removed, and changed assets."""
from __future__ import annotations

from typing import Dict, List, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Asset, AssetType, Scan, ScanDiff


def _asset_key(asset: Asset) -> Tuple[str, str]:
    return (asset.type.value if hasattr(asset.type, "value") else str(asset.type),
            (asset.name or "").lower())


async def compute_diff(
    db: AsyncSession, scan: Scan, baseline: Scan | None
) -> List[ScanDiff]:
    """Compute diffs between a scan and its baseline (previous completed scan)."""
    # Remove any prior diffs for this scan
    existing = await db.execute(select(ScanDiff).where(ScanDiff.scan_id == scan.id))
    for d in existing.scalars():
        await db.delete(d)

    if baseline is None:
        return []

    current = (await db.execute(
        select(Asset).where(Asset.scan_id == scan.id)
    )).scalars().all()
    previous = (await db.execute(
        select(Asset).where(Asset.scan_id == baseline.id)
    )).scalars().all()

    cur_map: Dict[Tuple[str, str], Asset] = {_asset_key(a): a for a in current}
    prev_map: Dict[Tuple[str, str], Asset] = {_asset_key(a): a for a in previous}

    diffs: List[ScanDiff] = []

    # New assets
    for key, asset in cur_map.items():
        if key not in prev_map:
            diffs.append(ScanDiff(
                scan_id=scan.id,
                baseline_scan_id=baseline.id,
                change_type="new",
                asset_type=asset.type.value,
                asset_name=asset.name,
                detail={"properties": asset.properties},
            ))

    # Removed assets
    for key, asset in prev_map.items():
        if key not in cur_map:
            diffs.append(ScanDiff(
                scan_id=scan.id,
                baseline_scan_id=baseline.id,
                change_type="removed",
                asset_type=asset.type.value,
                asset_name=asset.name,
                detail={"properties": asset.properties},
            ))

    # Changed assets (attention score or key properties)
    for key, asset in cur_map.items():
        if key in prev_map:
            old = prev_map[key]
            changes = {}
            if old.attention_score != asset.attention_score:
                changes["attention_score"] = {
                    "old": old.attention_score, "new": asset.attention_score,
                }
            old_props = old.properties or {}
            new_props = asset.properties or {}
            for prop in ("status_code", "server", "version", "cloud_provider",
                         "expired", "secret_count"):
                if old_props.get(prop) != new_props.get(prop):
                    changes[prop] = {"old": old_props.get(prop), "new": new_props.get(prop)}
            if changes:
                diffs.append(ScanDiff(
                    scan_id=scan.id,
                    baseline_scan_id=baseline.id,
                    change_type="changed",
                    asset_type=asset.type.value,
                    asset_name=asset.name,
                    detail=changes,
                ))

    db.add_all(diffs)
    return diffs
