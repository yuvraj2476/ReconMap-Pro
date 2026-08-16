"""ReconMap Pro local demonstration lab.

A tiny, intentionally realistic website used ONLY as an authorized scan target
for local development and the Docker Compose demo. It simulates a small
company with a main site, an API subdomain, a blog, and various assets so the
recon engine has something interesting to map.

This server is NOT a vulnerable-by-design CTF. It merely exposes the kinds of
metadata and links a recon platform is built to catalogue.
"""
from __future__ import annotations

import http.server
import json
import os
import socketserver
from urllib.parse import urlparse

PORT = int(os.environ.get("LAB_PORT", "8099"))
HOST = os.environ.get("LAB_HOST", "0.0.0.0")

# Simulate virtual subdomains via the Host header.
SITES = {
    "lab.local": {
        "title": "Acme Corp - Home",
        "nav": [("Home", "/"), ("API", "/api/"), ("Blog", "/blog/"),
                ("Docs", "/docs/"), ("Admin (demo)", "/admin/")],
        "body": """
        <h1>Welcome to Acme Corp</h1>
        <p>This is the corporate website of the Acme demo lab.</p>
        <p>Our public API lives at <a href="/api/v1/status">/api/v1/status</a>.</p>
        <script src="/static/app.js"></script>
        <script src="/static/vendor.js"></script>
        """,
        "server": "nginx/1.24.0",
        "powered_by": "PHP/8.2.12",
        "csp": True,
    },
    "api.lab.local": {
        "title": "Acme API",
        "nav": [("Status", "/api/v1/status"), ("Health", "/healthz"),
                ("Metrics", "/metrics"), ("Users", "/api/v1/users")],
        "body": """
        <h1>Acme Public API</h1>
        <p>REST API version 1.</p>
        <pre id="status">loading...</pre>
        <script>
        fetch('/api/v1/status').then(r=>r.json()).then(d=>{
          document.getElementById('status').textContent = JSON.stringify(d,null,2);
        });
        </script>
        """,
        "server": "nginx/1.24.0",
        "powered_by": None,
        "csp": False,
    },
    "blog.lab.local": {
        "title": "Acme Engineering Blog",
        "nav": [("Home", "/"), ("Posts", "/posts/"), ("About", "/about/")],
        "body": """
        <h1>Engineering Blog</h1>
        <article>
          <h2><a href="/posts/launch">Launching our new API</a></h2>
          <p>Today we launched version 1 of our public API...</p>
        </article>
        <article>
          <h2><a href="/posts/security">Security at Acme</a></h2>
          <p>How we think about security headers and CSP...</p>
        </article>
        <script src="/static/blog.js"></script>
        """,
        "server": "nginx/1.24.0",
        "powered_by": "Next.js",
        "csp": True,
    },
}

# JavaScript assets (static strings)
JS_ASSETS = {
    "/static/app.js": """
// Acme main application bundle
const API_BASE = '/api/v1';
const STRIPE_KEY = 'pk_test_demo1234567890abcdefghij';
const FEATURE_FLAGS = { newCheckout: true };
fetch(API_BASE + '/status').then(r => r.json()).then(console.log);
// TODO: add Sentry
""",
    "/static/vendor.js": """
/*! jQuery v3.7.1 | (c) JS Foundation */
window.jQuery = function(){ return {}; };
""",
    "/static/blog.js": """
// Blog bundle
const POSTS_API = '/api/v1/posts';
const GA_ID = 'G-XXXXXXXXXX';
""",
}

# API responses
API_ROUTES = {
    "/api/v1/status": lambda: {"status": "ok", "version": "1.0.0", "service": "acme-api"},
    "/api/v1/users": lambda: [{"id": 1, "name": "Ada"}, {"id": 2, "name": "Linus"}],
    "/api/v1/posts": lambda: [{"id": 1, "title": "Launch"}, {"id": 2, "title": "Security"}],
    "/healthz": lambda: {"status": "healthy"},
    "/metrics": lambda: "http_requests_total 1234\n",
}


class LabHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):  # quiet
        pass

    def _send(self, code, body, content_type="text/html; charset=utf-8", extra=None):
        if isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        host_header = self.headers.get("Host", "lab.local").split(":")[0]
        site = SITES.get(host_header, SITES["lab.local"])
        path = urlparse(self.path).path

        # Static JS assets
        if path in JS_ASSETS:
            self._send(200, JS_ASSETS[path], "application/javascript",
                       extra={"Server": site["server"],
                              "X-Powered-By": site["powered_by"] or ""} if site["powered_by"] else None)
            return

        # API routes
        if path in API_ROUTES:
            data = API_ROUTES[path]()
            if isinstance(data, dict) or isinstance(data, list):
                self._send(200, json.dumps(data), "application/json",
                           extra={"Server": site["server"],
                                  "Access-Control-Allow-Origin": "*"})
            else:
                self._send(200, data, "text/plain", extra={"Server": site["server"]})
            return

        # HTML pages
        nav = "".join(f'<a href="{href}">{label}</a>' for label, href in site["nav"])
        extra = {"Server": site["server"]}
        if site["powered_by"]:
            extra["X-Powered-By"] = site["powered_by"]
        if site["csp"]:
            extra["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'"
        else:
            # Deliberately missing CSP on the API subdomain
            extra["Access-Control-Allow-Origin"] = "*"

        if path == "/admin/":
            extra["X-Powered-By"] = "AdminPanel/2.1"
            body = "<h1>Admin Demo</h1><p>Demo admin interface (no auth in lab).</p>"
        elif path == "/blog/" or path == "/":
            body = site["body"]
        else:
            body = f"<h1>{path}</h1><p>Generated page for {path}.</p>"

        html = f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="generator" content="WordPress 6.4.2">
<title>{site['title']}</title>
</head><body>
<nav>{nav}</nav>
<main>{body}</main>
<footer>(c) Acme Lab</footer>
</body></html>"""
        self._send(200, html, "text/html; charset=utf-8", extra=extra)


class ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    print(f"[lab] serving on http://{HOST}:{PORT} (hosts: {', '.join(SITES)})")
    with ThreadedServer((HOST, PORT), LabHandler) as httpd:
        httpd.serve_forever()
