"""Report generation and dashboard stats endpoints."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.database import get_db
from app.models import Asset, AssetType, Observation, Scan, ScanStatus, Severity
from app.schemas import DashboardStats, ReportResponse
from app.services.reports import generate_report

router = APIRouter(tags=["reports"])


@router.get("/stats", response_model=DashboardStats)
async def dashboard_stats(db: AsyncSession = Depends(get_db)) -> DashboardStats:
    scans = (await db.execute(select(Scan).order_by(Scan.created_at.desc()))).scalars().all()
    total = len(scans)
    completed = [s for s in scans if s.status == ScanStatus.COMPLETED]
    latest = completed[0] if completed else (scans[0] if scans else None)

    asset_counts: Counter = Counter()
    severity_counts: Counter = Counter()
    technology_counts: Counter = Counter()

    if latest:
        assets = (await db.execute(
            select(Asset).where(Asset.scan_id == latest.id)
        )).scalars().all()
        for a in assets:
            asset_counts[a.type.value] += 1
            if a.type == AssetType.TECHNOLOGY:
                technology_counts[a.name] += 1
        obs = (await db.execute(
            select(Observation).where(Observation.scan_id == latest.id)
        )).scalars().all()
        for o in obs:
            severity_counts[o.severity.value] += 1

    return DashboardStats(
        total_scans=total,
        completed_scans=len(completed),
        latest_scan=latest,
        asset_counts=dict(asset_counts),
        severity_counts=dict(severity_counts),
        technology_counts=dict(technology_counts.most_common(20)),
    )


@router.post("/scans/{scan_id}/report", response_model=ReportResponse)
async def create_report(scan_id: str, db: AsyncSession = Depends(get_db)) -> ReportResponse:
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    if scan.status != ScanStatus.COMPLETED:
        raise HTTPException(status_code=409, detail="Scan must be completed to generate a report")
    path = await generate_report(db, scan_id, fmt="html")
    filename = Path(path).name
    return ReportResponse(
        scan_id=scan_id,
        target=scan.target,
        format="html",
        generated_at=datetime.now(timezone.utc),
        download_url=f"/api/reports/{filename}",
    )


@router.get("/reports/{filename}")
async def download_report(filename: str) -> FileResponse:
    settings = get_settings()
    # Prevent path traversal
    if "/" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    path = Path(settings.report_dir) / filename
    if not path.exists():
        raise HTTPException(status_code=404, detail="Report not found")
    return FileResponse(path, media_type="text/html", filename=filename)
