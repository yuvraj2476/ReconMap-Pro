"""Scan lifecycle endpoints."""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_db
from app.models import Scan, ScanStatus
from app.schemas import (
    MessageResponse,
    ScanCreate,
    ScanDetail,
    ScanListResponse,
    ScanResponse,
)
from app.security.scope import ScopeValidator
from app.workers import enqueue_scan

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanResponse, status_code=201)
async def create_scan(payload: ScanCreate, db: AsyncSession = Depends(get_db)) -> Scan:
    # Authorize the target immediately. We build a validator that ONLY permits
    # the requested domain (and its subdomains), proving operator consent.
    try:
        ScopeValidator.for_target(payload.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    scan = Scan(
        target=payload.target,
        status=ScanStatus.PENDING,
        passive_only=payload.passive_only,
        options={
            "max_depth": payload.max_depth,
            "max_pages": payload.max_pages,
            "enable_subdomain_bruteforce": payload.enable_subdomain_bruteforce,
        },
        stage="queued",
        message="Scan queued. Authorization confirmed for " + payload.target,
    )
    db.add(scan)
    await db.flush()
    await db.commit()
    await db.refresh(scan)

    await enqueue_scan(scan.id)
    return scan


@router.get("", response_model=ScanListResponse)
async def list_scans(
    target: Optional[str] = None,
    status: Optional[ScanStatus] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
) -> ScanListResponse:
    stmt = select(Scan).order_by(Scan.created_at.desc()).limit(limit).offset(offset)
    if target:
        stmt = stmt.where(Scan.target == target.lower())
    if status:
        stmt = stmt.where(Scan.status == status)
    result = await db.execute(stmt)
    scans = result.scalars().all()
    count_stmt = select(Scan)
    if target:
        count_stmt = count_stmt.where(Scan.target == target.lower())
    if status:
        count_stmt = count_stmt.where(Scan.status == status)
    total = len((await db.execute(count_stmt)).scalars().all())
    return ScanListResponse(scans=scans, total=total)


@router.get("/{scan_id}", response_model=ScanDetail)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)) -> ScanDetail:
    result = await db.execute(
        select(Scan)
        .where(Scan.id == scan_id)
        .options(
            selectinload(Scan.assets),
            selectinload(Scan.observations),
            selectinload(Scan.diffs),
            selectinload(Scan.relations),
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    detail = ScanDetail.model_validate(scan)
    detail.asset_count = len(scan.assets)
    detail.relation_count = len(scan.relations)
    detail.observation_count = len(scan.observations)
    detail.assets = scan.assets[:200]
    detail.observations = scan.observations
    detail.diffs = scan.diffs
    return detail


@router.delete("/{scan_id}", response_model=MessageResponse)
async def delete_scan(scan_id: str, db: AsyncSession = Depends(get_db)) -> MessageResponse:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status == ScanStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Cannot delete a running scan")
    await db.delete(scan)
    await db.commit()
    return MessageResponse(message="Scan deleted")
