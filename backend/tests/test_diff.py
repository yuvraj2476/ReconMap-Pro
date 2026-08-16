"""Scan diff tests."""
from __future__ import annotations

import pytest

from app.models import Asset, AssetType, Scan, ScanStatus
from app.services.diff import compute_diff


@pytest.mark.asyncio
async def test_diff_detects_new_removed_changed():
    from app.database import init_db, session_scope
    await init_db()
    async with session_scope() as db:
        # Baseline scan
        s1 = Scan(target="example.com", status=ScanStatus.COMPLETED)
        db.add(s1)
        await db.flush()
        db.add_all([
            Asset(scan_id=s1.id, type=AssetType.URL, name="https://example.com/a",
                  attention_score=10, properties={"status_code": 200}),
            Asset(scan_id=s1.id, type=AssetType.URL, name="https://example.com/old",
                  attention_score=10, properties={"status_code": 200}),
        ])
        await db.flush()

        # New scan: 'a' changed score, 'old' removed, 'new' added
        s2 = Scan(target="example.com", status=ScanStatus.COMPLETED)
        db.add(s2)
        await db.flush()
        db.add_all([
            Asset(scan_id=s2.id, type=AssetType.URL, name="https://example.com/a",
                  attention_score=50, properties={"status_code": 200}),
            Asset(scan_id=s2.id, type=AssetType.URL, name="https://example.com/new",
                  attention_score=10, properties={"status_code": 200}),
        ])
        await db.flush()

        diffs = await compute_diff(db, s2, s1)
        types = {d.change_type for d in diffs}
        assert "new" in types
        assert "removed" in types
        assert "changed" in types
        new_names = {d.asset_name for d in diffs if d.change_type == "new"}
        removed_names = {d.asset_name for d in diffs if d.change_type == "removed"}
        assert "https://example.com/new" in new_names
        assert "https://example.com/old" in removed_names
