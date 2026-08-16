"""Plain-English statement of what ReconMap Pro will and will not do.

These are enforced throughout the codebase (see :mod:`app.security.scope` and
the recon modules). They are surfaced in the UI and reports so operators have
an auditable declaration of intent.
"""
from __future__ import annotations

from typing import List

ALLOWED: List[str] = [
    "Passive subdomain discovery from certificate transparency logs",
    "DNS record enumeration (A, AAAA, CNAME, MX, TXT, NS, SOA) for in-scope domains",
    "HTTP/HTTPS banner and header analysis for in-scope, public hosts",
    "Technology fingerprinting from response bodies and headers",
    "Scope-aware, rate-limited web crawling of in-scope hosts",
    "Public URL/API endpoint extraction from HTML and JavaScript",
    "JavaScript asset download and static analysis (string extraction only)",
    "IP-to-ASN/organization attribution from WHOIS/RDAP and DNS",
    "Historical scan comparison and new/removed asset detection",
    "Inventory, graph, scoring, and professional report generation",
]

BLOCKED: List[str] = [
    "Active scanning of any host not in the explicitly authorized scope",
    "Requests to private, loopback, link-local, or reserved IP ranges (SSRF)",
    "Requests to cloud metadata endpoints (169.254.169.254 and equivalents) - always blocked",
    "Credential stuffing, password spraying, or brute-force attacks",
    "Exploitation of vulnerabilities or injection of payloads",
    "WAF/CAPTCHA bypass or evasion/stealth techniques",
    "Denial-of-service or destructive actions",
    "Port scanning outside the authorized scope",
    "Access to or exfiltration of data not exposed publicly",
    "Any action that violates the target's terms of service or applicable law",
]

USAGE_REQUIREMENT = (
    "ReconMap Pro is intended exclusively for authorized security testing. "
    "You must have explicit, documented permission to test every target. "
    "The operator assumes all responsibility for lawful use."
)


def describe_policies() -> dict:
    return {
        "usage_requirement": USAGE_REQUIREMENT,
        "allowed": ALLOWED,
        "blocked": BLOCKED,
    }
