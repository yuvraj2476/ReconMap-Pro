"""ReconMap Pro command-line interface.

Usage:
    python -m app.cli scan example.com
    python -m app.cli report <scan_id>
    python -m app.cli list
"""
from __future__ import annotations

import asyncio
import json
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from app.config import get_settings
from app.database import init_db, session_scope
from app.models import Asset, Scan, ScanStatus
from app.security.policies import describe_policies
from app.security.scope import ScopeValidator
from app.services.reports import generate_report
from app.services.scan_manager import run_scan
from sqlalchemy import select

cli = typer.Typer(help="ReconMap Pro CLI - authorized attack-surface intelligence")
console = Console()


@cli.command()
def policies() -> None:
    """Print the platform's safety policies."""
    p = describe_policies()
    console.print("[bold red]AUTHORIZED USE ONLY[/bold red]")
    console.print(p["usage_requirement"])
    console.print("\n[bold green]ALLOWED:[/bold green]")
    for item in p["allowed"]:
        console.print(f"  + {item}")
    console.print("\n[bold red]BLOCKED:[/bold red]")
    for item in p["blocked"]:
        console.print(f"  - {item}")


@cli.command()
def scan(
    target: str = typer.Argument(..., help="Authorized root domain (e.g. example.com)"),
    passive: bool = typer.Option(False, "--passive", help="Passive-only mode"),
    active_subdomains: bool = typer.Option(False, "--active-subdomains", help="Enable constrained subdomain wordlist"),
    max_depth: int = typer.Option(2, "--max-depth"),
    max_pages: int = typer.Option(50, "--max-pages"),
    allow_private: bool = typer.Option(False, "--allow-private", help="Permit private networks (LOCAL LAB ONLY)"),
) -> None:
    """Run an authorized scan against a target domain."""
    settings = get_settings()
    is_lab = target.endswith(".local") or target.endswith(".lab") or target in settings.lab_authorized_domains_list
    if allow_private or is_lab or settings.allow_private_networks:
        settings.allow_private_networks = True
        allow_private = True

    # Authorize scope
    try:
        ScopeValidator.for_target(target, allow_private_networks=allow_private)
    except ValueError as exc:
        console.print(f"[red]Invalid target: {exc}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold cyan]ReconMap Pro[/bold cyan] scanning [bold]{target}[/bold]")
    console.print(f"  passive_only={passive} active_subdomains={active_subdomains} "
                  f"max_depth={max_depth} max_pages={max_pages}")

    async def _run() -> str:
        await init_db()
        async with session_scope() as db:
            s = Scan(
                target=target,
                status=ScanStatus.PENDING,
                passive_only=passive,
                options={
                    "max_depth": max_depth,
                    "max_pages": max_pages,
                    "enable_subdomain_bruteforce": active_subdomains,
                    "allow_private_networks": allow_private,
                },
            )
            db.add(s)
            await db.flush()
            scan_id = s.id
        await run_scan(scan_id)
        return scan_id

    scan_id = asyncio.run(_run())
    console.print(f"\n[green]Scan complete: {scan_id}[/green]")

    # Print summary
    async def _summary() -> None:
        from sqlalchemy import func, select
        from app.models import Asset as A, Observation as O
        async with session_scope() as db:
            s = await db.get(Scan, scan_id)
            asset_count = (
                await db.execute(select(func.count()).select_from(A).where(A.scan_id == scan_id))
            ).scalar() or 0
            obs_count = (
                await db.execute(select(func.count()).select_from(O).where(O.scan_id == scan_id))
            ).scalar() or 0
            assets = (await db.execute(
                select(A).where(A.scan_id == scan_id)
                .order_by(A.attention_score.desc()).limit(20)
            )).scalars().all()

            table = Table(title=f"Top assets for {target}")
            table.add_column("Score", justify="right")
            table.add_column("Type")
            table.add_column("Name")
            table.add_column("Source")
            for a in assets:
                score_color = "red" if a.attention_score >= 70 else "yellow" if a.attention_score >= 40 else "green"
                table.add_row(
                    f"[{score_color}]{a.attention_score}[/{score_color}]",
                    a.type.value,
                    a.name[:80],
                    a.source,
                )
            console.print(table)
            console.print(f"\nTotal assets: {asset_count}, observations: {obs_count}")

    asyncio.run(_summary())


@cli.command(name="list")
def list_scans(limit: int = 20) -> None:
    """List recent scans."""
    from app.database import session_scope

    async def _q():
        await init_db()
        async with session_scope() as db:
            rows = (await db.execute(
                select(Scan).order_by(Scan.created_at.desc()).limit(limit)
            )).scalars().all()
            table = Table(title="Recent scans")
            table.add_column("ID")
            table.add_column("Target")
            table.add_column("Status")
            table.add_column("Progress")
            table.add_column("Assets")
            table.add_column("Created")
            # Fetch asset counts per scan in one query to avoid lazy loading.
            from sqlalchemy import func
            counts = {
                row[0]: row[1] for row in (
                    await db.execute(
                        select(Asset.scan_id, func.count(Asset.id))
                        .where(Asset.scan_id.in_([s.id for s in rows]))
                        .group_by(Asset.scan_id)
                    )
                ).all()
            }
            for s in rows:
                table.add_row(
                    s.id[:8], s.target, s.status.value, f"{int(s.progress)}%",
                    str(counts.get(s.id, 0)), s.created_at.isoformat(timespec="seconds"),
                )
            console.print(table)

    asyncio.run(_q())


@cli.command()
def report(scan_id: str, output: Optional[str] = None) -> None:
    """Generate an HTML report for a completed scan."""
    async def _gen():
        await init_db()
        async with session_scope() as db:
            path = await generate_report(db, scan_id, fmt="html")
            console.print(f"[green]Report written:[/green] {path}")
    asyncio.run(_gen())


if __name__ == "__main__":
    cli()
