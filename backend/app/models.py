"""SQLAlchemy ORM models for the ReconMap Pro asset graph and scan history."""
from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class AssetType(str, enum.Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    ASN = "asn"
    ORGANIZATION = "organization"
    CERTIFICATE = "certificate"
    TECHNOLOGY = "technology"
    URL = "url"
    API = "api"
    JAVASCRIPT = "javascript"
    DNS_RECORD = "dns_record"
    HOSTING = "hosting"
    WEB_SERVER = "web_server"


class RelationType(str, enum.Enum):
    HAS_SUBDOMAIN = "has_subdomain"
    RESOLVES_TO = "resolves_to"
    ANNOUNCED_BY = "announced_by"
    OWNED_BY = "owned_by"
    PRESENTS = "presents"
    USES = "uses"
    HOSTED_BY = "hosted_by"
    SERVED_BY = "served_by"
    LINKS_TO = "links_to"
    EXPOSES = "exposes"
    REFERENCES = "references"
    HAS_DNS = "has_dns"


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #
class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    target: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING, index=True)
    progress: Mapped[float] = mapped_column(Float, default=0.0)
    stage: Mapped[str] = mapped_column(String(120), default="queued")
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    passive_only: Mapped[bool] = mapped_column(Boolean, default=False)
    options: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    assets: Mapped[List["Asset"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    relations: Mapped[List["Relation"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    observations: Mapped[List["Observation"]] = relationship(back_populates="scan", cascade="all, delete-orphan")
    diffs: Mapped[List["ScanDiff"]] = relationship(
        "ScanDiff", back_populates="scan", cascade="all, delete-orphan",
        foreign_keys="ScanDiff.scan_id",
    )


# --------------------------------------------------------------------------- #
# Assets
# --------------------------------------------------------------------------- #
class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (UniqueConstraint("scan_id", "type", "name", name="uq_asset_scan_type_name"),)

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    type: Mapped[AssetType] = mapped_column(Enum(AssetType), index=True)
    name: Mapped[str] = mapped_column(Text, index=True)
    properties: Mapped[dict] = mapped_column(JSON, default=dict)
    attention_score: Mapped[int] = mapped_column(Integer, default=0)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    source: Mapped[str] = mapped_column(String(120), default="unknown")
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped["Scan"] = relationship(back_populates="assets")


# --------------------------------------------------------------------------- #
# Relations (the edges of the attack-surface graph)
# --------------------------------------------------------------------------- #
class Relation(Base):
    __tablename__ = "relations"
    __table_args__ = (
        UniqueConstraint("scan_id", "source_id", "target_id", "type", name="uq_relation"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    source_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    target_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    type: Mapped[RelationType] = mapped_column(Enum(RelationType), index=True)
    properties: Mapped[dict] = mapped_column(JSON, default=dict)
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    source: Mapped[str] = mapped_column(String(120), default="unknown")
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped["Scan"] = relationship(back_populates="relations")


# --------------------------------------------------------------------------- #
# Security observations
# --------------------------------------------------------------------------- #
class Observation(Base):
    __tablename__ = "observations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    asset_id: Mapped[Optional[str]] = mapped_column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    title: Mapped[str] = mapped_column(String(255))
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.INFO, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    recommendation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    cwe: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(120), default="unknown")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped["Scan"] = relationship(back_populates="observations")


# --------------------------------------------------------------------------- #
# Scan diff (historical change detection)
# --------------------------------------------------------------------------- #
class ScanDiff(Base):
    __tablename__ = "scan_diffs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=_uuid)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    baseline_scan_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("scans.id", ondelete="SET NULL"), nullable=True
    )
    change_type: Mapped[str] = mapped_column(String(20), index=True)  # new | removed | changed
    asset_type: Mapped[str] = mapped_column(String(40))
    asset_name: Mapped[str] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped["Scan"] = relationship(back_populates="diffs", foreign_keys=[scan_id])
