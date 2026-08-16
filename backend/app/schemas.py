"""Pydantic v2 schemas for the public REST API."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from app.models import AssetType, RelationType, ScanStatus, Severity


# --- Scan -------------------------------------------------------------------
class ScanCreate(BaseModel):
    target: str = Field(..., description="Authorized root domain to scan, e.g. example.com")
    passive_only: bool = False
    max_depth: Optional[int] = Field(default=None, ge=0, le=5)
    max_pages: Optional[int] = Field(default=None, ge=1, le=500)
    enable_subdomain_bruteforce: bool = False

    @field_validator("target")
    @classmethod
    def normalize_target(cls, v: str) -> str:
        v = (v or "").strip().lower()
        if "://" in v:
            from urllib.parse import urlparse
            v = urlparse(v).hostname or v
        if not v:
            raise ValueError("target is required")
        return v


class ScanResponse(BaseModel):
    id: str
    target: str
    status: ScanStatus
    progress: float
    stage: str
    message: Optional[str] = None
    error: Optional[str] = None
    passive_only: bool
    options: Dict[str, Any] = Field(default_factory=dict)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanListResponse(BaseModel):
    scans: List[ScanResponse]
    total: int


# --- Assets / Relations -----------------------------------------------------
class AssetResponse(BaseModel):
    id: str
    scan_id: str
    type: AssetType
    name: str
    properties: Dict[str, Any] = Field(default_factory=dict)
    attention_score: int = 0
    confidence: float = 1.0
    source: str = "unknown"
    evidence: Optional[str] = None
    first_seen: datetime
    last_seen: datetime

    model_config = {"from_attributes": True}


class RelationResponse(BaseModel):
    id: str
    source_id: str
    target_id: str
    type: RelationType
    properties: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = 1.0
    source: str = "unknown"
    evidence: Optional[str] = None
    timestamp: datetime

    model_config = {"from_attributes": True}


class GraphNode(BaseModel):
    data: Dict[str, Any]


class GraphEdge(BaseModel):
    data: Dict[str, Any]


class GraphResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class AssetListResponse(BaseModel):
    assets: List[AssetResponse]
    total: int


class ObservationResponse(BaseModel):
    id: str
    asset_id: Optional[str] = None
    title: str
    severity: Severity
    description: str
    recommendation: Optional[str] = None
    cwe: Optional[str] = None
    evidence: Optional[str] = None
    source: str
    created_at: datetime

    model_config = {"from_attributes": True}


class DiffResponse(BaseModel):
    id: str
    baseline_scan_id: Optional[str] = None
    change_type: str
    asset_type: str
    asset_name: str
    detail: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime

    model_config = {"from_attributes": True}


class ScanDetail(ScanResponse):
    asset_count: int = 0
    relation_count: int = 0
    observation_count: int = 0
    assets: List[AssetResponse] = Field(default_factory=list)
    observations: List[ObservationResponse] = Field(default_factory=list)
    diffs: List[DiffResponse] = Field(default_factory=list)


# --- Scope / policy ---------------------------------------------------------
class ScopeAuthorization(BaseModel):
    target: str
    authorized: bool
    normalized: str
    reason: Optional[str] = None


class PolicyResponse(BaseModel):
    usage_requirement: str
    allowed: List[str]
    blocked: List[str]


# --- Stats ------------------------------------------------------------------
class DashboardStats(BaseModel):
    total_scans: int
    completed_scans: int
    latest_scan: Optional[ScanResponse] = None
    asset_counts: Dict[str, int] = Field(default_factory=dict)
    severity_counts: Dict[str, int] = Field(default_factory=dict)
    technology_counts: Dict[str, int] = Field(default_factory=dict)


# --- Report -----------------------------------------------------------------
class ReportResponse(BaseModel):
    scan_id: str
    target: str
    format: str
    generated_at: datetime
    download_url: str


# --- Generic ----------------------------------------------------------------
class MessageResponse(BaseModel):
    message: str
