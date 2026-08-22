"""Scan orchestration.

Runs all reconnaissance stages against an authorized target, persists assets,
relations and observations, computes attention scores, and generates a diff
against the previous scan. This is the heart of ReconMap Pro.
"""
from __future__ import annotations

import asyncio
import logging
import traceback
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.models import (
    Asset,
    AssetType,
    Observation,
    Relation,
    RelationType,
    Scan,
    ScanStatus,
    Severity,
)
from app.recon.certificates import fetch_certificate
from app.recon.crawler import crawl
from app.recon.dns import enumerate_dns
from app.recon.http_analysis import analyze_http
from app.recon.http_client import SafeHttpClient
from app.recon.exposed_source import check_exposed_code
from app.recon.ip_asn import lookup_ips
from app.recon.js_analysis import analyze_js_bundle
from app.recon.subdomains import discover_subdomains
from app.security.scope import ScopeValidator
from app.services.diff import compute_diff
from app.services.scoring import score_assets

logger = logging.getLogger(__name__)


class ScanContext:
    """In-memory accumulator for a running scan."""

    def __init__(self, scan: Scan, settings: Settings) -> None:
        self.scan = scan
        self.settings = settings
        self.assets: Dict[tuple, Asset] = {}
        self.relations: List[Relation] = []
        self.observations: List[Observation] = []
        self._asset_ids: Dict[tuple, str] = {}
        self.stage = "initializing"
        self.progress = 0.0

    def add_asset(
        self,
        asset_type: AssetType,
        name: str,
        *,
        properties: Optional[dict] = None,
        confidence: float = 1.0,
        source: str = "unknown",
        evidence: Optional[str] = None,
    ) -> Asset:
        key = (asset_type, name.lower())
        if key in self.assets:
            existing = self.assets[key]
            # Merge properties
            if properties:
                merged = dict(existing.properties or {})
                merged.update(properties)
                existing.properties = merged
            existing.confidence = max(existing.confidence, confidence)
            return existing
        asset = Asset(
            id=str(uuid.uuid4()),
            scan_id=self.scan.id,
            type=asset_type,
            name=name,
            properties=properties or {},
            confidence=confidence,
            source=source,
            evidence=evidence,
        )
        self.assets[key] = asset
        return asset

    def add_relation(
        self,
        source: Asset,
        target: Asset,
        rel_type: RelationType,
        *,
        confidence: float = 1.0,
        source_module: str = "unknown",
        evidence: Optional[str] = None,
        properties: Optional[dict] = None,
    ) -> None:
        self.relations.append(Relation(
            id=str(uuid.uuid4()),
            scan_id=self.scan.id,
            source_id=source.id,
            target_id=target.id,
            type=rel_type,
            confidence=confidence,
            source=source_module,
            evidence=evidence,
            properties=properties or {},
        ))

    def add_observation(
        self,
        title: str,
        severity: Severity,
        *,
        asset: Optional[Asset] = None,
        description: str = "",
        recommendation: Optional[str] = None,
        cwe: Optional[str] = None,
        evidence: Optional[str] = None,
        source: str = "unknown",
    ) -> Observation:
        obs = Observation(
            scan_id=self.scan.id,
            asset_id=asset.id if asset else None,
            title=title,
            severity=severity,
            description=description,
            recommendation=recommendation,
            cwe=cwe,
            evidence=evidence,
            source=source,
        )
        self.observations.append(obs)
        return obs


async def _run_scan(ctx: ScanContext, db: AsyncSession, settings: Settings) -> None:
    scan = ctx.scan
    target = scan.target
    allow_private = (
        settings.allow_private_networks
        or scan.options.get("allow_private_networks", False)
        or target.endswith(".local")
    )
    validator = ScopeValidator.for_target(
        target, allow_private_networks=allow_private
    )

    # Root domain asset
    root = ctx.add_asset(AssetType.DOMAIN, target, source="target", confidence=1.0)

    def _set_stage(stage: str, progress: float) -> None:
        ctx.stage = stage
        ctx.progress = progress
        scan.stage = stage
        scan.progress = progress

    # ------------------------------------------------------------------ #
    # Stage 1: DNS enumeration
    # ------------------------------------------------------------------ #
    _set_stage("dns-enumeration", 5)
    await db.flush()
    logger.info("[%s] Stage: DNS enumeration", scan.id)

    dns = await enumerate_dns(target, validator)
    for rtype, values in dns.records.items():
        for value in values:
            rec = ctx.add_asset(
                AssetType.DNS_RECORD, f"{rtype} {value}",
                properties={"rtype": rtype, "value": value, "domain": target},
                source="dns", confidence=1.0,
                evidence=f"{rtype} record for {target}",
            )
            ctx.add_relation(root, rec, RelationType.HAS_DNS, source_module="dns",
                             evidence=f"DNS {rtype}")

    # DMARC
    for dmarc in dns.dmarc:
        rec = ctx.add_asset(
            AssetType.DNS_RECORD, f"TXT _dmarc.{target}",
            properties={"rtype": "TXT", "value": dmarc, "domain": f"_dmarc.{target}",
                        "is_dmarc": True},
            source="dns", confidence=1.0,
        )
        ctx.add_relation(root, rec, RelationType.HAS_DNS, source_module="dns")
        if "p=none" in dmarc.lower():
            ctx.add_observation(
                "DMARC policy set to none", Severity.LOW, asset=root,
                description="The DMARC record is configured with p=none, which "
                            "monitors but does not enforce email authentication.",
                recommendation="Consider setting p=quarantine or p=reject after "
                               "monitoring legitimate mail flows.",
                source="dns",
            )
        if "p=reject" in dmarc.lower() or "p=quarantine" in dmarc.lower():
            ctx.add_observation(
                "Strong DMARC policy configured", Severity.INFO, asset=root,
                description="DMARC enforces a quarantine/reject policy.",
                source="dns",
            )

    # SPF check
    spf_records = [v for v in dns.records.get("TXT", []) if v.lower().startswith("v=spf1")]
    if not spf_records:
        ctx.add_observation(
            "No SPF record found", Severity.LOW, asset=root,
            description="No TXT record beginning with v=spf1 was found, allowing "
                        "email spoofing of the domain.",
            recommendation="Publish an SPF record listing authorized senders.",
            source="dns",
        )

    # ------------------------------------------------------------------ #
    # Stage 2: Subdomain discovery (passive CT + optional active)
    # ------------------------------------------------------------------ #
    _set_stage("subdomain-discovery", 15)
    await db.flush()
    logger.info("[%s] Stage: subdomain discovery", scan.id)

    enable_active = bool(scan.options.get("enable_subdomain_bruteforce", False)) and not scan.passive_only
    subdomains = await discover_subdomains(
        target, validator, settings, enable_active=enable_active
    )
    sub_assets: List[Asset] = []
    for sub in subdomains:
        if sub == target:
            # The root is already represented as a DOMAIN asset; don't duplicate.
            sub_assets.append(root)
            continue
        sub_asset = ctx.add_asset(
            AssetType.SUBDOMAIN, sub,
            properties={"is_root": False},
            source="crt.sh",
            confidence=0.95,
            evidence=f"Discovered via certificate transparency",
        )
        ctx.add_relation(root, sub_asset, RelationType.HAS_SUBDOMAIN,
                         source_module="subdomains",
                         evidence=f"{target} -> {sub}")
        sub_assets.append(sub_asset)

    # ------------------------------------------------------------------ #
    # Stage 3: IP resolution + ASN/org attribution
    # ------------------------------------------------------------------ #
    _set_stage("ip-asn-attribution", 30)
    await db.flush()
    logger.info("[%s] Stage: IP/ASN attribution", scan.id)

    # Collect all IPs from DNS and from resolving every subdomain
    all_ips: Set[str] = set(dns.all_ips)
    for sub in subdomains:
        ips = await validator.resolve(sub)
        all_ips.update(ips)

    ip_infos = await lookup_ips(sorted(all_ips), validator._resolver)  # noqa: SLF001
    ip_assets: Dict[str, Asset] = {}
    for ip, info in ip_infos.items():
        if info.is_private and not settings.allow_private_networks:
            continue
        props = {
            "asn": info.asn, "org": info.org, "isp": info.isp,
            "country": info.country, "cloud_provider": info.cloud_provider,
            "network_name": info.network_name, "cidr": info.cidr,
            "reverse_dns": info.reverse_dns,
        }
        ip_asset = ctx.add_asset(
            AssetType.IP, ip,
            properties=props,
            source="rdap/cymru" if not info.cloud_provider else "cloud-signatures",
            confidence=0.9,
            evidence=f"ASN {info.asn or 'unknown'} / {info.org or info.cloud_provider or 'unknown'}",
        )
        ip_assets[ip] = ip_asset

        # ASN
        if info.asn:
            asn_asset = ctx.add_asset(
                AssetType.ASN, f"AS{info.asn}",
                properties={"asn": info.asn, "org": info.org},
                source="cymru", confidence=0.9,
            )
            ctx.add_relation(ip_asset, asn_asset, RelationType.ANNOUNCED_BY,
                             source_module="ip_asn")
            if info.org:
                org_asset = ctx.add_asset(
                    AssetType.ORGANIZATION, info.org,
                    properties={"country": info.country},
                    source="rdap", confidence=0.85,
                )
                ctx.add_relation(asn_asset, org_asset, RelationType.OWNED_BY,
                                 source_module="ip_asn")
        # Cloud / hosting
        if info.cloud_provider:
            hosting = ctx.add_asset(
                AssetType.HOSTING, info.cloud_provider,
                properties={"provider": info.cloud_provider},
                source="cloud-signatures", confidence=0.95,
            )
            ctx.add_relation(ip_asset, hosting, RelationType.HOSTED_BY,
                             source_module="ip_asn")

    # Link subdomains -> IPs
    for sub in subdomains:
        ips = await validator.resolve(sub)
        sub_asset = (
            ctx.assets.get((AssetType.SUBDOMAIN, sub.lower()))
            or ctx.assets.get((AssetType.DOMAIN, sub.lower()))
        )
        if not sub_asset:
            continue
        sub_asset.properties["resolved_ips"] = ips
        for ip in ips:
            ip_asset = ip_assets.get(ip)
            if ip_asset:
                ctx.add_relation(sub_asset, ip_asset, RelationType.RESOLVES_TO,
                                 source_module="dns", evidence=f"A/AAAA record",
                                 confidence=1.0)

    # ------------------------------------------------------------------ #
    # Stage 4: Certificates (for all subdomains that have an IP)
    # ------------------------------------------------------------------ #
    _set_stage("certificates", 45)
    await db.flush()
    logger.info("[%s] Stage: certificates", scan.id)

    for host in subdomains:
        host_asset = (
            ctx.assets.get((AssetType.SUBDOMAIN, host.lower()))
            or ctx.assets.get((AssetType.DOMAIN, host.lower()))
        )
        if not host_asset:
            continue
        try:
            cert = await fetch_certificate(host, validator)
        except Exception:
            continue
        if cert.error and "verify" not in cert.error:
            host_asset.properties["cert_error"] = cert.error
            continue
        props = {
            "issuer": cert.issuer, "subject": cert.subject,
            "serial": cert.serial, "not_before": cert.not_before,
            "not_after": cert.not_after, "san": cert.san[:50],
            "san_count": len(cert.san), "signature_algorithm": cert.signature_algorithm,
            "expired": cert.expired, "verify_error": cert.error,
            "self_signed": cert.issuer == cert.subject if cert.issuer else False,
        }
        # Expires soon (within 30 days)?
        if cert.not_after:
            try:
                from datetime import datetime as dt
                naive = dt.strptime(cert.not_after, "%b %d %H:%M:%S %Y %Z")
                props["expires_soon"] = (naive - dt.utcnow()).days <= 30
                props["expires_soon"] = props["expires_soon"] and not cert.expired
            except Exception:
                props["expires_soon"] = False

        cert_asset = ctx.add_asset(
            AssetType.CERTIFICATE, f"{host} cert",
            properties=props,
            source="tls", confidence=1.0,
            evidence=f"Issuer: {cert.issuer}",
        )
        ctx.add_relation(host_asset, cert_asset, RelationType.PRESENTS,
                         source_module="certificates",
                         evidence=f"TLS handshake with {host}")
        if cert.expired:
            ctx.add_observation(
                "Expired TLS certificate", Severity.HIGH, asset=cert_asset,
                description=f"The certificate for {host} has expired (notAfter={cert.not_after}).",
                recommendation="Renew the certificate immediately.",
                cwe="CWE-295", source="certificates",
            )
        if props.get("expires_soon"):
            ctx.add_observation(
                "TLS certificate expiring soon", Severity.MEDIUM, asset=cert_asset,
                description=f"The certificate for {host} expires on {cert.not_after}.",
                recommendation="Renew the certificate before expiry.",
                cwe="CWE-295", source="certificates",
            )
        if cert.error and "verify" in cert.error:
            ctx.add_observation(
                "TLS certificate verification error", Severity.MEDIUM, asset=cert_asset,
                description=f"Certificate for {host} failed verification: {cert.error}.",
                recommendation="Investigate the certificate chain and host configuration.",
                cwe="CWE-295", source="certificates",
            )

    # ------------------------------------------------------------------ #
    # Stage 5: HTTP analysis + crawling
    # ------------------------------------------------------------------ #
    _set_stage("http-analysis", 60)
    await db.flush()
    logger.info("[%s] Stage: HTTP analysis & crawl", scan.id)

    max_depth = scan.options.get("max_depth", settings.max_crawl_depth)
    max_pages = scan.options.get("max_pages", settings.max_crawl_pages)

    async with SafeHttpClient(validator, settings) as client:
        for host in subdomains:
            # The host may be the root domain (represented as a DOMAIN asset)
            # or a subdomain (SUBDOMAIN asset). Resolve whichever exists.
            host_asset = (
                ctx.assets.get((AssetType.SUBDOMAIN, host.lower()))
                or ctx.assets.get((AssetType.DOMAIN, host.lower()))
            )

            # Build the list of (scheme, port) candidates to probe. In
            # production only 80/443 are attempted.
            candidates = [("https", 443), ("http", 80)]

            reachable_found = False
            for scheme, port in candidates:
                if port in (80, 443):
                    url = f"{scheme}://{host}/"
                else:
                    url = f"{scheme}://{host}:{port}/"
                try:
                    analysis = await analyze_http(url, client, validator)
                except Exception:
                    continue
                if not analysis.reachable:
                    continue
                reachable_found = True

                # Codebase checks
                try:
                    exposed_codebases = await check_exposed_code(url, client, validator)
                    for ec in exposed_codebases:
                        ec_props = {
                            "is_exposed_code": True,
                            "code_type": ec["code_type"],
                            "size_bytes": ec["size_bytes"],
                            "size_human": ec["size_human"],
                            "download_url": ec["url"],
                            "path": ec["path"],
                        }
                        ec_asset = ctx.add_asset(
                            AssetType.URL, ec["url"],
                            properties=ec_props,
                            source="exposed-scanner", confidence=1.0,
                            evidence=f"Exposed codebase {ec['code_type']} found (estimated size: {ec['size_human']})",
                        )
                        if host_asset:
                            ctx.add_relation(host_asset, ec_asset, RelationType.LINKS_TO,
                                             source_module="exposed-scanner")
                        
                        ctx.add_observation(
                            f"Exposed codebase backup detected: {ec['code_type']}", Severity.HIGH,
                            asset=ec_asset,
                            description=f"An exposed codebase/backup was found at {ec['url']}. "
                                        f"This leak can expose private credentials, algorithms, or API endpoints. "
                                        f"Estimated codebase size is {ec['size_human']}.",
                            recommendation="Restrict public access to this path immediately, delete any unnecessary files, "
                                           "and rotate any credentials found in the codebase.",
                            source="exposed-scanner",
                        )
                except Exception as exc:
                    logger.debug("Codebase checks failed for %s: %s", url, exc)

                # Web server asset
                if analysis.server:
                    server_asset = ctx.add_asset(
                        AssetType.WEB_SERVER, analysis.server,
                        properties={"server": analysis.server, "host": host},
                        source="http", confidence=0.9,
                        evidence=f"Server header: {analysis.server}",
                    )
                    if host_asset:
                        ctx.add_relation(host_asset, server_asset, RelationType.SERVED_BY,
                                         source_module="http")

                # Technology assets
                for tech in analysis.technologies:
                    tech_asset = ctx.add_asset(
                        AssetType.TECHNOLOGY, tech.name,
                        properties={
                            "category": tech.category,
                            "version": tech.version,
                            "cpe": tech.cpe,
                            "host": host,
                        },
                        source="fingerprint", confidence=tech.confidence / 100,
                        evidence=tech.evidence,
                    )
                    if host_asset:
                        ctx.add_relation(host_asset, tech_asset, RelationType.USES,
                                         source_module="tech", evidence=tech.evidence)

                # URL asset for the root page
                url_props = {
                    "status_code": analysis.status_code,
                    "content_type": analysis.content_type,
                    "title": analysis.title,
                    "server": analysis.server,
                    "elapsed_ms": analysis.elapsed_ms,
                    "scheme": scheme,
                    "missing_security_headers": analysis.security_headers_missing,
                    "present_security_headers": analysis.security_headers_present,
                    "is_api": False,
                }
                url_asset = ctx.add_asset(
                    AssetType.URL, analysis.final_url,
                    properties=url_props,
                    source="http", confidence=1.0,
                    evidence=f"HTTP {analysis.status_code}",
                )
                if host_asset:
                    ctx.add_relation(host_asset, url_asset, RelationType.LINKS_TO,
                                     source_module="http")

                # Security header observations
                if scheme == "https":
                    if "strict-transport-security" in analysis.security_headers_missing:
                        ctx.add_observation(
                            "Missing HSTS header", Severity.MEDIUM, asset=url_asset,
                            description="The Strict-Transport-Security header is "
                                        "missing over HTTPS.",
                            recommendation="Enable HSTS with a long max-age.",
                            cwe="CWE-319", source="http",
                        )
                    if "content-security-policy" in analysis.security_headers_missing:
                        ctx.add_observation(
                            "Missing Content-Security-Policy", Severity.LOW, asset=url_asset,
                            description="No CSP header is set, increasing XSS impact.",
                            recommendation="Define a restrictive CSP.",
                            cwe="CWE-699", source="http",
                        )
                    if "x-frame-options" in analysis.security_headers_missing:
                        ctx.add_observation(
                            "Missing X-Frame-Options", Severity.LOW, asset=url_asset,
                            description="Pages may be vulnerable to clickjacking.",
                            recommendation="Set X-Frame-Options DENY or SAMEORIGIN.",
                            cwe="CWE-1021", source="http",
                        )
                    if "x-content-type-options" in analysis.security_headers_missing:
                        ctx.add_observation(
                            "Missing X-Content-Type-Options", Severity.LOW, asset=url_asset,
                            description="Browsers may MIME-sniff responses.",
                            recommendation="Set X-Content-Type-Options: nosniff.",
                            cwe="CWE-16", source="http",
                        )
                else:
                    ctx.add_observation(
                        "Service available over plaintext HTTP", Severity.MEDIUM, asset=url_asset,
                        description=f"{host} is reachable over HTTP without redirecting to HTTPS.",
                        recommendation="Redirect all HTTP traffic to HTTPS and enable HSTS.",
                        cwe="CWE-319", source="http",
                    )

                # Cookie observations
                for cookie in analysis.cookies:
                    if not cookie.get("secure") and scheme == "https":
                        ctx.add_observation(
                            f"Cookie {cookie['name']} missing Secure flag", Severity.LOW,
                            asset=url_asset,
                            description="A cookie set over HTTPS lacks the Secure attribute.",
                            recommendation="Add the Secure flag to all cookies.",
                            cwe="CWE-614", source="http",
                        )
                    if not cookie.get("httponly"):
                        ctx.add_observation(
                            f"Cookie {cookie['name']} missing HttpOnly flag", Severity.LOW,
                            asset=url_asset,
                            description="A cookie is accessible to JavaScript, increasing XSS impact.",
                            recommendation="Set the HttpOnly flag on session cookies.",
                            cwe="CWE-1004", source="http",
                        )

                # Version disclosure observations
                if analysis.powered_by:
                    ctx.add_observation(
                        "Technology version disclosure (X-Powered-By)", Severity.INFO,
                        asset=url_asset,
                        description=f"Server advertises {analysis.powered_by} via X-Powered-By.",
                        recommendation="Remove version-disclosing headers in production.",
                        source="http",
                    )

                # Crawl only the first reachable host
                if host == subdomains[0] and reachable_found:
                    _set_stage("crawling", 75)
                    await db.flush()
                    try:
                        crawl_result = await crawl(
                            url, client, validator, settings,
                            max_depth=max_depth, max_pages=max_pages,
                        )
                    except Exception as exc:
                        logger.warning("Crawl failed: %s", exc)
                        crawl_result = None

                    if crawl_result:
                        for page in crawl_result.pages:
                            if page.url == url:
                                continue
                            page_asset = ctx.add_asset(
                                AssetType.API if page.is_api else AssetType.URL,
                                page.url,
                                properties={
                                    "status_code": page.status_code,
                                    "content_type": page.content_type,
                                    "title": page.title,
                                    "depth": page.depth,
                                    "is_api": page.is_api,
                                    "is_javascript": page.is_javascript,
                                },
                                source="crawler", confidence=0.95,
                                evidence=f"Depth {page.depth}, HTTP {page.status_code}",
                            )
                            if host_asset:
                                rel = RelationType.EXPOSES if page.is_api else RelationType.LINKS_TO
                                ctx.add_relation(host_asset, page_asset, rel,
                                                 source_module="crawler",
                                                 evidence=f"<a href> or <form action>")

                        # JS analysis
                        if crawl_result.js_assets:
                            _set_stage("javascript-analysis", 85)
                            await db.flush()
                            js_results = await analyze_js_bundle(
                                crawl_result.js_assets[:30], client, validator
                            )
                            for js in js_results:
                                if not js.fetchable:
                                    continue
                                js_asset = ctx.add_asset(
                                    AssetType.JAVASCRIPT, js.url,
                                    properties={
                                        "size": js.size,
                                        "endpoint_count": len(js.endpoints),
                                        "url_count": len(js.urls),
                                        "secret_count": len(js.secrets),
                                        "source_map": js.source_map,
                                    },
                                    source="js-analysis", confidence=0.9,
                                    evidence=f"{len(js.endpoints)} endpoints, {len(js.secrets)} secret indicators",
                                )
                                page_asset = ctx.assets.get(
                                    (AssetType.URL if not js.url.endswith(".js") else AssetType.JAVASCRIPT,
                                     js.url.lower())
                                )
                                if host_asset:
                                    ctx.add_relation(host_asset, js_asset, RelationType.REFERENCES,
                                                     source_module="js-analysis")
                                if js.source_map:
                                    ctx.add_observation(
                                        "JavaScript source map exposed", Severity.LOW,
                                        asset=js_asset,
                                        description=f"A source map is referenced at {js.source_map}, "
                                                    "which may expose original source code.",
                                        recommendation="Do not deploy source maps to production "
                                                       "or restrict access to them.",
                                        cwe="CWE-540", source="js-analysis",
                                    )
                                for secret in js.secrets:
                                    ctx.add_observation(
                                        f"Potential secret in JavaScript: {secret['type']}",
                                        Severity.HIGH, asset=js_asset,
                                        description=f"A pattern matching {secret['type']} was found "
                                                    f"in {js.url} (entropy={secret['entropy']}). "
                                                    "This is a heuristic indicator and requires manual review.",
                                        recommendation="Rotate the credential if valid and remove it "
                                                       "from client-side code. Use environment variables "
                                                       "and a secrets manager.",
                                        cwe="CWE-798", evidence=secret["preview"],
                                        source="js-analysis",
                                    )
                                for endpoint in js.endpoints[:50]:
                                    ep_asset = ctx.add_asset(
                                        AssetType.API, endpoint,
                                        properties={"source": "javascript", "from_js": js.url},
                                        source="js-analysis", confidence=0.7,
                                        evidence=f"Extracted string from {js.url}",
                                    )
                                    ctx.add_relation(js_asset, ep_asset, RelationType.REFERENCES,
                                                     source_module="js-analysis")
                    break  # Only crawl the first reachable HTTPS host

    # ------------------------------------------------------------------ #
    # Stage 6: Persist, score and diff
    # ------------------------------------------------------------------ #
    _set_stage("scoring", 95)
    await db.flush()

    # Flush assets so they have IDs for relations
    for asset in ctx.assets.values():
        db.add(asset)
    await db.flush()

    for relation in ctx.relations:
        db.add(relation)
    for obs in ctx.observations:
        db.add(obs)

    # Score all assets
    score_assets(list(ctx.assets.values()), ctx.observations)

    # Diff against previous scan
    previous = (await db.execute(
        select(Scan).where(
            Scan.target == target,
            Scan.status == ScanStatus.COMPLETED,
            Scan.id != scan.id,
        ).order_by(Scan.completed_at.desc()).limit(1)
    )).scalar_one_or_none()

    if previous:
        await compute_diff(db, scan, previous)
        # Surface new high-value assets as observations
        from app.models import ScanDiff
        new_diffs = (await db.execute(
            select(ScanDiff).where(ScanDiff.scan_id == scan.id, ScanDiff.change_type == "new")
        )).scalars().all()
        for d in new_diffs:
            if d.asset_type in ("api", "subdomain", "javascript"):
                ctx.add_observation(
                    f"New {d.asset_type} discovered: {d.asset_name}",
                    Severity.MEDIUM,
                    description=f"New asset {d.asset_name} was not present in the previous scan.",
                    source="diff",
                )

    ctx.stage = "completed"
    ctx.progress = 100
    scan.status = ScanStatus.COMPLETED
    scan.stage = "completed"
    scan.message = "Scan completed successfully"
    scan.completed_at = datetime.now(timezone.utc)
    scan.progress = 100
    await db.flush()


async def run_scan(scan_id: str) -> None:
    """Entry point used by both the API and the worker queue."""
    from app.database import session_scope

    settings = get_settings()
    async with session_scope() as db:
        scan = await db.get(Scan, scan_id)
        if not scan:
            logger.error("Scan %s not found", scan_id)
            return

        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        scan.progress = 0
        scan.stage = "starting"
        await db.flush()

        ctx = ScanContext(scan, settings)
        try:
            await _run_scan(ctx, db, settings)
        except Exception as exc:
            logger.exception("Scan %s failed", scan_id)
            scan.status = ScanStatus.FAILED
            scan.error = f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[-2000:]}"
            scan.stage = "failed"
            scan.completed_at = datetime.now(timezone.utc)
            await db.flush()
