"""ReconMap Pro FastAPI application entry point."""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import assets, health, reports, scans, scope
from app.config import get_settings
from app.database import init_db
from app.workers import get_queue

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("reconmap")


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    Path(settings.report_dir).mkdir(parents=True, exist_ok=True)
    await init_db()
    logger.info("%s started (env=%s)", settings.app_name, settings.environment)
    yield
    queue = get_queue()
    await queue.shutdown()
    logger.info("ReconMap Pro shut down cleanly")


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="ReconMap Pro",
        description=(
            "Authorization-first attack-surface intelligence platform. "
            "For authorized security testing only."
        ),
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router, prefix="/api")
    app.include_router(scans.router, prefix="/api")
    app.include_router(assets.router, prefix="/api")
    app.include_router(reports.router, prefix="/api")
    app.include_router(scope.router, prefix="/api")

    # Serve the built React frontend if present (single-container deployment).
    # In development Vite runs on :5173 and proxies /api to this backend.
    frontend_dist = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    serve_frontend = frontend_dist.exists() and not settings.debug

    if serve_frontend:
        assets_dir = frontend_dist / "assets"
        if assets_dir.exists():
            app.mount(
                "/assets",
                StaticFiles(directory=str(assets_dir)),
                name="frontend-assets",
            )

        @app.get("/")
        async def spa_root():
            return FileResponse(frontend_dist / "index.html")

        @app.get("/{full_path:path}")
        async def spa(full_path: str):
            # Don't shadow API/docs routes
            if full_path.startswith(("api/", "docs", "openapi.json", "redoc")):
                return {"detail": "not found"}
            index = frontend_dist / "index.html"
            if index.exists():
                return FileResponse(index)
            return {"detail": "not found"}
    else:
        @app.get("/")
        async def root() -> dict:
            return {
                "name": settings.app_name,
                "version": "1.0.0",
                "docs": "/docs",
                "policies": "/api/policies",
                "frontend": "not built (run npm run build in frontend/)",
                "authorized_use_only": True,
            }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=settings.debug)
