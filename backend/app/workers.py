"""Background task queue.

Uses arq + Redis when ``RECONMAP_REDIS_URL`` is set; otherwise falls back to
an in-process asyncio task so the platform runs with zero external
dependencies (used by the dev server and the bundled Docker lab).
"""
from __future__ import annotations

import asyncio
import logging
from typing import Optional

from app.config import get_settings
from app.services.scan_manager import run_scan

logger = logging.getLogger(__name__)


class InProcessQueue:
    """Fallback queue that runs scans as asyncio tasks in the API process."""

    def __init__(self) -> None:
        self._tasks: dict[str, asyncio.Task] = {}

    async def enqueue(self, scan_id: str) -> None:
        if scan_id in self._tasks and not self._tasks[scan_id].done():
            return
        task = asyncio.create_task(self._run(scan_id))
        self._tasks[scan_id] = task

    async def _run(self, scan_id: str) -> None:
        try:
            await run_scan(scan_id)
        except Exception:
            logger.exception("Scan %s crashed", scan_id)

    async def shutdown(self) -> None:
        for task in self._tasks.values():
            task.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)


_queue: Optional[InProcessQueue] = None


def get_queue() -> InProcessQueue:
    global _queue
    if _queue is None:
        _queue = InProcessQueue()
    return _queue


async def enqueue_scan(scan_id: str) -> None:
    """Enqueue a scan. Uses Redis/arq if configured, else in-process."""
    settings = get_settings()
    if settings.redis_url:
        await _enqueue_arq(settings.redis_url, scan_id)
    else:
        await get_queue().enqueue(scan_id)


async def _enqueue_arq(redis_url: str, scan_id: str) -> None:  # pragma: no cover
    try:
        from arq import create_pool
        from arq.connections import RedisSettings

        redis = await create_pool(RedisSettings.from_dsn(redis_url))
        await redis.enqueue_job("run_scan", scan_id)
    except Exception as exc:
        logger.warning("arq enqueue failed (%s); falling back to in-process", exc)
        await get_queue().enqueue(scan_id)


# arq worker function --------------------------------------------------------
async def arq_run_scan(ctx: dict, scan_id: str) -> None:  # pragma: no cover
    await run_scan(scan_id)


class WorkerSettings:  # pragma: no cover
    """arq worker settings. Run with: arq app.workers.WorkerSettings"""
    functions = [arq_run_scan]
    queue_name = "reconmap"
