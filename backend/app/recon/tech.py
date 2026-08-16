"""Technology fingerprinting.

A compact, self-contained fingerprint engine inspired by Wappalyzer. It
inspects HTTP headers, cookies and response HTML/meta tags and returns
matched technologies with category, confidence and evidence.

Fingerprints are deliberately conservative (high precision, lower recall)
so results are trustworthy for an attack-surface report.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.recon.http_client import FetchResult


@dataclass
class TechMatch:
    name: str
    category: str
    version: Optional[str] = None
    confidence: int = 100
    evidence: str = ""
    cpe: Optional[str] = None


@dataclass
class Fingerprint:
    name: str
    category: str
    website: str = ""
    cpe: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: List[str] = field(default_factory=list)
    html_patterns: List[re.Pattern] = field(default_factory=list)
    meta: Dict[str, str] = field(default_factory=dict)
    script_patterns: List[re.Pattern] = field(default_factory=list)
    implies: List[str] = field(default_factory=list)


def _p(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


# A focused, high-signal fingerprint set covering common web tech.
FINGERPRINTS: List[Fingerprint] = [
    # --- Web servers -------------------------------------------------------
    Fingerprint("Nginx", "Web Server", website="https://nginx.org", cpe="cpe:2.3:a:nginx:nginx",
                headers={"server": r"nginx(?:/([\d.]+))?"}),
    Fingerprint("Apache HTTP Server", "Web Server", website="https://httpd.apache.org",
                cpe="cpe:2.3:a:apache:http_server",
                headers={"server": r"apache(?:/([\d.]+))?"}),
    Fingerprint("Microsoft-IIS", "Web Server", website="https://iis.net",
                headers={"server": r"microsoft-iis/([\d.]+)"}),
    Fingerprint("Caddy", "Web Server", website="https://caddyserver.com",
                headers={"server": r"caddy(?:v?([\d.]+))?"}),
    Fingerprint("Cloudflare", "CDN/Proxy", website="https://cloudflare.com",
                headers={"cf-ray": r".", "server": r"cloudflare"}),
    Fingerprint("Akamai", "CDN/Proxy", website="https://akamai.com",
                headers={"x-akamai-transformed": r".", "server": r"AkamaiGHost"}),
    Fingerprint("Fastly", "CDN/Proxy", website="https://fastly.com",
                headers={"x-served-by": r"cache-.*", "via": r"varnish"}),
    Fingerprint("Amazon CloudFront", "CDN", website="https://aws.amazon.com/cloudfront",
                headers={"x-amz-cf-id": r".", "via": r"cloudfront"}),
    Fingerprint("Vercel", "Hosting", website="https://vercel.com",
                headers={"x-vercel-id": r".", "server": r"vercel"}),
    Fingerprint("Netlify", "Hosting", website="https://netlify.com",
                headers={"server": r"Netlify", "x-nf-request-id": r"."}),

    # --- Languages / frameworks -------------------------------------------
    Fingerprint("PHP", "Programming Language", website="https://php.net",
                cpe="cpe:2.3:a:php:php",
                headers={"x-powered-by": r"php/?([\d.]*)?"},
                cookies=["phpsessid"],
                html_patterns=[_p(r"\.php(\?|\"|')")]),
    Fingerprint("ASP.NET", "Web Framework", website="https://asp.net",
                headers={"x-powered-by": r"asp\.net", "x-aspnet-version": r"([\d.]+)"},
                cookies=["asp.net_sessionid", "asp_session_id"]),
    Fingerprint("Express", "Web Framework", website="https://expressjs.com",
                headers={"x-powered-by": r"express"}),
    Fingerprint("Django", "Web Framework", website="https://djangoproject.com",
                cookies=["csrftoken", "sessionid"],
                html_patterns=[_p(r"csrfmiddlewaretoken")]),
    Fingerprint("Flask", "Web Framework", website="https://flask.palletsprojects.com",
                cookies=["session"]),
    Fingerprint("Rails", "Web Framework", website="https://rubyonrails.org",
                headers={"x-runtime": r".", "x-request-id": r"."},
                html_patterns=[_p(r"<meta[^>]+content=\"authenticity_token\"")],
                cookies=["_session_id"]),
    Fingerprint("Next.js", "JavaScript Framework", website="https://nextjs.org",
                html_patterns=[_p(r"/_next/static/"), _p(r"__next")],
                headers={"x-powered-by": r"next\.js"}),
    Fingerprint("Nuxt.js", "JavaScript Framework", website="https://nuxt.com",
                html_patterns=[_p(r"/_nuxt/"), _p(r"__nuxt")]),
    Fingerprint("React", "JavaScript Library", website="https://react.dev",
                html_patterns=[_p(r"data-reactroot"), _p(r"data-react-helmet")],
                script_patterns=[_p(r"react(?:-dom)?(?:\.production|\.development)?\.js"),
                                 _p(r"react@?[\d.]*")]),
    Fingerprint("Vue.js", "JavaScript Framework", website="https://vuejs.org",
                html_patterns=[_p(r"data-v-[0-9a-f]")],
                script_patterns=[_p(r"vue(?:\.runtime)?(?:\.min)?\.js")]),
    Fingerprint("Angular", "JavaScript Framework", website="https://angular.io",
                html_patterns=[_p(r"ng-version="), _p(r"ng-app")],
                script_patterns=[_p(r"angular(?:\.min)?\.js"), _p(r"@angular/core")]),
    Fingerprint("jQuery", "JavaScript Library", website="https://jquery.com",
                script_patterns=[_p(r"jquery[.-]([\d.]+)(?:\.min)?\.js")]),
    Fingerprint("WordPress", "CMS", website="https://wordpress.org",
                cpe="cpe:2.3:a:wordpress:wordpress",
                html_patterns=[_p(r"wp-content"), _p(r"wp-includes"),
                               _p(r"<meta[^>]+name=\"generator\"[^>]+wordpress\s*([\d.]*)")],
                headers={"link": r"wp-json"}),
    Fingerprint("Drupal", "CMS", website="https://drupal.org",
                html_patterns=[_p(r"sites/(?:default|all)/"), _p(r"Drupal\.settings")],
                headers={"x-generator": r"Drupal(?:\s([\d.]+))?"}),
    Fingerprint("Joomla", "CMS", website="https://joomla.org",
                html_patterns=[_p(r"/media/system/js/"), _p(r"joomla")]),
    Fingerprint("Ghost", "CMS", website="https://ghost.org",
                html_patterns=[_p(r"ghost/head"), _p(r"ghost-url")]),
    Fingerprint("Hugo", "Static Site Generator", website="https://gohugo.io",
                html_patterns=[_p(r"<meta[^>]+name=\"generator\"[^>]+hugo\s*([\d.]*)")]),
    Fingerprint("Jekyll", "Static Site Generator", website="https://jekyllrb.com",
                html_patterns=[_p(r"<meta[^>]+name=\"generator\"[^>]+jekyll\s*([\d.]*)")]),
    Fingerprint("Gatsby", "Static Site Generator", website="https://gatsbyjs.com",
                html_patterns=[_p(r"___gatsby")]),
    Fingerprint("Tailwind CSS", "CSS Framework", website="https://tailwindcss.com",
                html_patterns=[_p(r"class=\"[^\"]*\b(?:flex|grid|container|mx-auto)\b[^\"]*\""),
                               _p(r"tailwind(?:\.min)?\.css")]),
    Fingerprint("Bootstrap", "CSS Framework", website="https://getbootstrap.com",
                html_patterns=[_p(r"bootstrap(?:\.min)?\.css")]),
    Fingerprint("Google Analytics", "Analytics", website="https://analytics.google.com",
                html_patterns=[_p(r"google-analytics\.com/(?:ga|analytics)\.js"),
                               _p(r"googletagmanager\.com/gtag/js"),
                               _p(r"gtag\(")]),
    Fingerprint("Tag Manager", "Tag Manager", website="https://tagmanager.google.com",
                html_patterns=[_p(r"googletagmanager\.com/gtm\.js")]),
    Fingerprint("Stripe", "Payment", website="https://stripe.com",
                html_patterns=[_p(r"js\.stripe\.com"), _p(r"stripe\.publishableKey")]),
    Fingerprint("reCAPTCHA", "Security", website="https://google.com/recaptcha",
                html_patterns=[_p(r"google\.com/recaptcha"), _p(r"grecaptcha")]),
    Fingerprint("Cloudflare Turnstile", "Security", website="https://challenges.cloudflare.com",
                html_patterns=[_p(r"challenges\.cloudflare\.com/turnstile")]),
    Fingerprint("HubSpot", "Marketing", website="https://hubspot.com",
                html_patterns=[_p(r"js\.hs-analytics\.net"), _p(r"js\.hs-scripts\.com")]),
    Fingerprint("Intercom", "Customer Support", website="https://intercom.com",
                html_patterns=[_p(r"widget\.intercom\.io"), _p(r"intercomSettings")]),
    Fingerprint("Sentry", "Monitoring", website="https://sentry.io",
                html_patterns=[_p(r"sentry\.io/[0-9]"), _p(r"__SENTRY__")]),
    Fingerprint("Datadog", "Monitoring", website="https://datadoghq.com",
                html_patterns=[_p(r"datadoghq-browser-agent")]),
    Fingerprint("Google Tag Manager", "Analytics", website="https://marketingplatform.google.com",
                html_patterns=[_p(r"googletagmanager\.com")]),
    Fingerprint("Docker Registry", "Container", website="https://distribution.github.io/distribution/",
                headers={"docker-distribution-api-version": r".*"}),
    Fingerprint("Kubernetes", "Orchestration", website="https://kubernetes.io",
                headers={"server": r"kube-.*"}),
    Fingerprint("Consul", "Infrastructure", website="https://consul.io",
                headers={"x-consul-index": r".*"}),
]


def _match_header_pattern(pattern: str, value: str) -> Optional[str]:
    m = re.search(pattern, value, re.IGNORECASE)
    if not m:
        return None
    if m.groups():
        return m.group(1) or None
    return None


def fingerprint(fetch: FetchResult) -> List[TechMatch]:
    """Return matched technologies for a fetched page."""
    headers_lower = {k.lower(): v for k, v in fetch.headers.items()}
    cookies = []
    set_cookie = headers_lower.get("set-cookie", "")
    if set_cookie:
        cookies = [c.strip().split("=")[0].lower() for c in set_cookie.split(";") if "=" in c]

    html = fetch.text or ""
    matches: Dict[str, TechMatch] = {}
    implied: List[str] = []

    for fp in FINGERPRINTS:
        evidence_parts: List[str] = []
        version: Optional[str] = None
        confidence = 100

        # Headers
        for hname, hpat in fp.headers.items():
            val = headers_lower.get(hname.lower())
            if val:
                v = _match_header_pattern(hpat, val)
                if v is not None or re.search(hpat, val, re.IGNORECASE):
                    evidence_parts.append(f"header {hname}: {val[:80]}")
                    if v:
                        version = v
                    break

        # Cookies
        for cookie in fp.cookies:
            if cookie in cookies:
                evidence_parts.append(f"cookie {cookie}")
                break

        # HTML patterns
        for pat in fp.html_patterns:
            m = pat.search(html)
            if m:
                evidence_parts.append(f"html: {m.group(0)[:80]}")
                if m.groups() and m.group(1) and version is None:
                    version = m.group(1)
                break

        # Script patterns
        for pat in fp.script_patterns:
            m = pat.search(html)
            if m:
                evidence_parts.append(f"script: {m.group(0)[:80]}")
                if m.groups() and m.group(1) and version is None:
                    version = m.group(1)
                break

        # Meta generator
        if fp.meta:
            for mname, mpat in fp.meta.items():
                m = re.search(
                    rf"<meta[^>]+name=[\"']{re.escape(mname)}[\"'][^>]+content=[\"']([^\"']*)[\"']",
                    html, re.IGNORECASE,
                )
                if m and re.search(mpat, m.group(1), re.IGNORECASE):
                    evidence_parts.append(f"meta {mname}: {m.group(1)[:80]}")
                    break

        if evidence_parts:
            matches[fp.name] = TechMatch(
                name=fp.name,
                category=fp.category,
                version=version,
                confidence=confidence,
                evidence="; ".join(evidence_parts),
                cpe=fp.cpe,
            )
            implied.extend(fp.implies)

    return list(matches.values())
