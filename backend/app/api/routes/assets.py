"""Asset, observation and graph endpoints."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models import Asset, AssetType, Observation, Relation
from app.schemas import (
    AssetListResponse,
    AssetResponse,
    GraphResponse,
    ObservationResponse,
)
from app.services.graph import build_graph

router = APIRouter(prefix="/scans/{scan_id}", tags=["assets"])


@router.get("/graph", response_model=GraphResponse)
async def get_graph(scan_id: str, db: AsyncSession = Depends(get_db)) -> GraphResponse:
    graph = await build_graph(db, scan_id)
    return GraphResponse(**graph)


@router.get("/assets", response_model=AssetListResponse)
async def list_assets(
    scan_id: str,
    type: Optional[AssetType] = None,
    q: Optional[str] = None,
    min_score: int = Query(default=0, ge=0, le=100),
    limit: int = Query(default=500, le=2000),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
) -> AssetListResponse:
    stmt = select(Asset).where(Asset.scan_id == scan_id)
    if type:
        stmt = stmt.where(Asset.type == type)
    if q:
        stmt = stmt.where(Asset.name.ilike(f"%{q}%"))
    if min_score:
        stmt = stmt.where(Asset.attention_score >= min_score)
    stmt = stmt.order_by(Asset.attention_score.desc(), Asset.name).limit(limit).offset(offset)
    result = await db.execute(stmt)
    assets = result.scalars().all()
    return AssetListResponse(assets=assets, total=len(assets))


@router.get("/assets/{asset_id}", response_model=AssetResponse)
async def get_asset(
    scan_id: str, asset_id: str, db: AsyncSession = Depends(get_db)
) -> Asset:
    asset = await db.get(Asset, asset_id)
    if not asset or asset.scan_id != scan_id:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset


@router.get("/observations", response_model=List[ObservationResponse])
async def list_observations(
    scan_id: str,
    severity: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
) -> List[Observation]:
    stmt = select(Observation).where(Observation.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Observation.severity == severity)
    stmt = stmt.order_by(Observation.severity.desc(), Observation.created_at)
    result = await db.execute(stmt)
    return list(result.scalars().all())
