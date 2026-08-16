"""Professional report generation (Markdown + HTML)."""
from __future__ import annotations

import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from jinja2 import Environment, BaseLoader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.models import (
    Asset,
    AssetType,
    Observation,
    Relation,
    Scan,
    ScanDiff,
    Severity,
)
from app.security.policies import describe_policies

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>ReconMap Pro - Attack Surface Report - {{ scan.target }}</title>
<style>
  :root { --bg:#0b1220; --card:#111a2e; --text:#e2e8f0; --muted:#94a3b8;
          --accent:#38bdf8; --high:#f87171; --med:#fbbf24; --low:#60a5fa;
          --ok:#34d399; }
  *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--text);
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;line-height:1.6}
  .wrap{max-width:1100px;margin:0 auto;padding:40px 24px}
  h1{font-size:32px;margin:0 0 4px} h2{color:var(--accent);border-bottom:1px solid #1e293b;
    padding-bottom:8px;margin-top:40px}
  .meta{color:var(--muted);margin-bottom:24px}
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin:24px 0}
  .card{background:var(--card);border:1px solid #1e293b;border-radius:12px;padding:20px}
  .card .n{font-size:32px;font-weight:700;color:var(--accent)}
  .card .l{color:var(--muted);font-size:13px;text-transform:uppercase;letter-spacing:.05em}
  table{width:100%;border-collapse:collapse;margin:16px 0}
  th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #1e293b;font-size:14px;vertical-align:top}
  th{color:var(--muted);text-transform:uppercase;font-size:11px;letter-spacing:.06em}
  .sev{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600}
  .sev-high{background:rgba(248,113,113,.15);color:var(--high)}
  .sev-medium{background:rgba(251,191,36,.15);color:var(--med)}
  .sev-low{background:rgba(96,165,250,.15);color:var(--low)}
  .sev-info{background:rgba(148,163,184,.15);color:var(--muted)}
  code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:13px}
  .pol{background:var(--card);border-radius:12px;padding:20px;margin:12px 0}
  .pol h3{margin-top:0}
  footer{color:var(--muted);font-size:12px;text-align:center;margin-top:60px;padding-top:24px;
    border-top:1px solid #1e293b}
</style></head><body><div class="wrap">
  <h1>Attack Surface Report</h1>
  <div class="meta">
    <strong>{{ scan.target }}</strong> &middot; Scan started {{ scan.started_at }} &middot;
    completed {{ scan.completed_at }} &middot; ReconMap Pro
  </div>

  <div class="cards">
    <div class="card"><div class="n">{{ assets|length }}</div><div class="l">Assets</div></div>
    <div class="card"><div class="n">{{ relations|length }}</div><div class="l">Relations</div></div>
    <div class="card"><div class="n">{{ observations|length }}</div><div class="l">Observations</div></div>
    <div class="card"><div class="n">{{ diffs|length }}</div><div class="l">Changes</div></div>
  </div>

  <h2>Scope &amp; Authorization</h2>
  <p>{{ policies.usage_requirement }}</p>
  <div class="pol"><h3>Activities performed</h3><ul>
  {% for item in policies.allowed %}<li>{{ item }}</li>{% endfor %}
  </ul></div>
  <div class="pol"><h3>Activities explicitly not performed</h3><ul>
  {% for item in policies.blocked %}<li>{{ item }}</li>{% endfor %}
  </ul></div>

  <h2>Security Observations</h2>
  {% if observations %}
  <table><thead><tr><th>Severity</th><th>Title</th><th>Asset</th><th>Recommendation</th></tr></thead><tbody>
  {% for o in observations %}
  <tr>
    <td><span class="sev sev-{{ o.severity.value }}">{{ o.severity.value }}</span></td>
    <td><strong>{{ o.title }}</strong><br><span style="color:var(--muted);font-size:13px">{{ o.description }}</span></td>
    <td>{{ o.asset_name or '—' }}</td>
    <td>{{ o.recommendation or '—' }}</td>
  </tr>
  {% endfor %}
  </tbody></table>
  {% else %}<p>No observations.</p>{% endif %}

  <h2>Asset Inventory</h2>
  <table><thead><tr><th>Type</th><th>Name</th><th>Score</th><th>Source</th><th>Key Properties</th></tr></thead><tbody>
  {% for a in assets %}
  <tr>
    <td>{{ a.type.value }}</td>
    <td><code>{{ a.name }}</code></td>
    <td>{{ a.attention_score }}</td>
    <td>{{ a.source }}</td>
    <td style="color:var(--muted);font-size:12px">
      {% if a.type.value == 'technology' %}{{ a.properties.category }}{% if a.properties.version %} v{{ a.properties.version }}{% endif %}{% endif %}
      {% if a.properties.status_code %}HTTP {{ a.properties.status_code }}{% endif %}
      {% if a.properties.cloud_provider %}{{ a.properties.cloud_provider }}{% endif %}
      {% if a.properties.asn %}AS{{ a.properties.asn }}{% endif %}
    </td>
  </tr>
  {% endfor %}
  </tbody></table>

  {% if diffs %}
  <h2>Changes Since Previous Scan</h2>
  <table><thead><tr><th>Change</th><th>Type</th><th>Asset</th><th>Detail</th></tr></thead><tbody>
  {% for d in diffs %}
  <tr><td><strong>{{ d.change_type }}</strong></td><td>{{ d.asset_type }}</td>
  <td><code>{{ d.asset_name }}</code></td><td style="font-size:12px;color:var(--muted)">{{ d.detail }}</td></tr>
  {% endfor %}
  </tbody></table>
  {% endif %}

  <footer>Generated by ReconMap Pro at {{ generated_at }}. This report is for authorized
  security testing only.</footer>
</div></body></html>"""


async def generate_report(db: AsyncSession, scan_id: str, fmt: str = "html") -> str:
    settings = get_settings()
    scan = await db.get(Scan, scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    assets = (await db.execute(
        select(Asset).where(Asset.scan_id == scan_id).order_by(Asset.attention_score.desc())
    )).scalars().all()
    relations = (await db.execute(
        select(Relation).where(Relation.scan_id == scan_id)
    )).scalars().all()
    observations = (await db.execute(
        select(Observation).where(Observation.scan_id == scan_id).order_by(
            Observation.severity.desc()
        )
    )).scalars().all()
    diffs = (await db.execute(
        select(ScanDiff).where(ScanDiff.scan_id == scan_id)
    )).scalars().all()

    # Attach asset names to observations for display
    asset_map = {a.id: a for a in assets}
    obs_list = []
    for o in observations:
        d = {
            "severity": o.severity, "title": o.title, "description": o.description,
            "recommendation": o.recommendation, "asset_name": asset_map[o.asset_id].name if o.asset_id and o.asset_id in asset_map else None,
        }
        obs_list.append(type("O", (), d)())

    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(HTML_TEMPLATE)
    html = template.render(
        scan=scan,
        assets=assets,
        relations=relations,
        observations=obs_list,
        diffs=diffs,
        policies=describe_policies(),
        generated_at=datetime.now(timezone.utc).isoformat(),
    )

    report_dir = Path(settings.report_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    filename = f"reconmap_{scan.target}_{scan.id[:8]}.{fmt}"
    path = report_dir / filename
    path.write_text(html, encoding="utf-8")
    return str(path)
