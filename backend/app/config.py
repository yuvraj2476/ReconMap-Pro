"""ReconMap Pro configuration.

All settings are environment-driven. Safe-by-default security flags ensure
that active reconnaissance can only touch explicitly authorized scope.
"""
from __future__ import annotations

from functools import lru_cache
from typing import List

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="RECONMAP_", extra="ignore"
    )

    # --- Application ---------------------------------------------------------
    app_name: str = "ReconMap Pro"
    environment: str = Field(default="development")
    debug: bool = Field(default=False)
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)

    # --- Storage -------------------------------------------------------------
    # Defaults to SQLite for zero-dependency local dev/tests. In production the
    # docker-compose file sets this to asyncpg://...
    database_url: str = Field(
        default="sqlite+aiosqlite:///./reconmap.db",
        description="SQLAlchemy async database URL.",
    )
    redis_url: str = Field(
        default="", description="Redis URL. Empty = in-process queue/cache."
    )

    # --- Security / scope enforcement (SAFE BY DEFAULT) ----------------------
    # When True, private/loopback/link-local targets are permitted. This must
    # ONLY be enabled when running against the bundled local Docker lab.
    allow_private_networks: bool = Field(default=False)
    # Domains that are always treated as in-scope (the bundled lab), CSV in env.
    lab_authorized_domains: str = Field(default="lab.local,example.lab")

    @property
    def lab_authorized_domains_list(self) -> List[str]:
        return [d.strip() for d in self.lab_authorized_domains.split(",") if d.strip()]

    # --- Reconnaissance behaviour -------------------------------------------
    request_timeout: float = Field(default=10.0)
    max_redirects: int = Field(default=5)
    max_crawl_depth: int = Field(default=3)
    max_crawl_pages: int = Field(default=75)
    max_concurrent_requests: int = Field(default=8)
    user_agent: str = Field(
        default="ReconMapPro/1.0 (+authorized-security-research; contact: security@example.invalid)"
    )
    # Respect robots.txt for passive crawling guidance.
    respect_robots: bool = Field(default=True)
    # Passive-only mode disables active probing/bruteforce entirely.
    passive_only: bool = Field(default=False)
    # DNS bruteforce wordlist size cap (small by design; no brute-forcing).
    subdomain_wordlist_size: int = Field(default=120)

    # --- Reports -------------------------------------------------------------
    report_dir: str = Field(default="./reports")

    # --- Local lab only ------------------------------------------------------
    # When allow_private_networks is True (local Docker lab), also probe these
    # extra HTTP ports for each host. Empty in production. Comma-separated.
    lab_extra_ports: List[int] = Field(default_factory=list)

    @field_validator("lab_extra_ports", mode="before")
    @classmethod
    def _parse_ports(cls, v):
        if v is None or v == "":
            return []
        if isinstance(v, str):
            return [int(p.strip()) for p in v.split(",") if p.strip()]
        if isinstance(v, int):
            return [v]
        return list(v)

    # --- CORS ----------------------------------------------------------------
    # Stored as a comma-separated string in env; split into a list via property.
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:8080,http://localhost:8000"
    )

    @property
    def cors_origins_list(self) -> List[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def is_postgres(self) -> bool:
        return self.database_url.startswith("postgresql") or self.database_url.startswith(
            "postgres"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
