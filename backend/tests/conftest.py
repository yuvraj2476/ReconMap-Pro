"""Pytest fixtures."""
from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

# Ensure the backend package is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Use an isolated SQLite database for tests
os.environ["RECONMAP_DATABASE_URL"] = "sqlite+aiosqlite:///./test_reconmap.db"
os.environ["RECONMAP_REDIS_URL"] = ""
os.environ["RECONMAP_REPORT_DIR"] = "./test_reports"


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(autouse=True)
def _clean_db():
    """Remove test DB between tests."""
    db_path = Path("./test_reconmap.db")
    if db_path.exists():
        db_path.unlink()
    yield
    if db_path.exists():
        db_path.unlink()
