"""Async database engine, session factory and declarative base."""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

logger = logging.getLogger(__name__)

_settings = get_settings()

_engine: Optional[AsyncEngine] = None
_sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


def _make_engine() -> AsyncEngine:
    url = _settings.database_url
    connect_args = {}
    if _settings.is_sqlite:
        connect_args = {"check_same_thread": False}
    kwargs = dict(
        echo=_settings.debug,
        future=True,
        pool_pre_ping=True,
    )
    if _settings.is_postgres:
        kwargs["pool_size"] = 10
        kwargs["max_overflow"] = 20
    engine = create_async_engine(url, connect_args=connect_args, **kwargs)
    return engine


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        _engine = _make_engine()
    return _engine


def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    global _sessionmaker
    if _sessionmaker is None:
        _sessionmaker = async_sessionmaker(
            bind=get_engine(), expire_on_commit=False, class_=AsyncSession
        )
    return _sessionmaker


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    """Transactional session context manager."""
    session = get_sessionmaker()()
    try:
        yield session
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    async with session_scope() as session:
        yield session


async def init_db() -> None:
    """Create all tables. In production use Alembic migrations."""
    from app import models  # noqa: F401 - ensure models are registered

    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database initialised at %s", _settings.database_url)
