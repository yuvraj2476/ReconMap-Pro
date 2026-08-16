# ReconMap Pro

**Authorization-first attack-surface intelligence platform.**

ReconMap Pro maps an authorized domain into an interactive infrastructure
graph — subdomains, DNS records, IPs, ASNs, organizations, certificates,
hosting/CDN, frontend and backend technologies, web servers, URLs, public API
endpoints, JavaScript assets and historical changes.

> **For authorized security testing only.** Every active request is validated
> against an explicitly authorized scope. Private/loopback/link-local ranges
> and cloud metadata endpoints are blocked by default (SSRF protection). The
> platform does not brute-force, exploit, bypass defences or perform any
> destructive action.

![architecture](docs/architecture.svg)

## Features

| # | Capability |
|---|------------|
| 1 | Subdomain discovery (Certificate Transparency + optional constrained wordlist) |
| 2 | DNS enumeration (A, AAAA, CNAME, MX, NS, TXT, SOA, DMARC, SPF) |
| 3 | Certificate / domain discovery (TLS metadata, SANs, expiry) |
| 4 | HTTP/HTTPS analysis (status, headers, cookies, security headers) |
| 5 | IP → ASN / organization / cloud attribution (RDAP + Team Cymru + CIDR signatures) |
| 6 | Technology fingerprinting (50+ fingerprints; Wappalyzer-style engine) |
| 7 | Scope-aware, rate-limited web crawler (depth/page caps, no form submission) |
| 8 | Public URL/API endpoint discovery |
| 9 | JavaScript asset analysis (endpoints, URLs, secret indicators, source maps) |
| 10 | Interactive attack-surface graph (Cytoscape.js) |
| 11 | Asset inventory with search and filtering |
| 12 | Scan history and diff (new / removed / changed) |
| 13 | New/removed asset detection |
| 14 | Security observations (CWE-mapped, severity-rated) |
| 15 | Asset attention / prioritization score (0–100) |
| 16 | Professional HTML reports |
| 17 | CLI (`python -m app.cli`) |
| 18 | REST API (OpenAPI/Swagger at `/docs`) |
| 19 | Local Docker demonstration lab |

Every graph relationship stores **source, timestamp, confidence and evidence**.

## Architecture

```
┌──────────────┐     ┌──────────────────────────────────────────────┐
│  React + Vite│     │ FastAPI backend (async)                      │
│  TypeScript  │────▶│ ┌──────────┐  ┌───────────────────────────┐  │
│  Tailwind    │     │ │ REST API │  │ Scan orchestrator         │  │
│  Cytoscape   │     │ └────┬─────┘  │  ├─ DNS enumeration       │  │
└──────────────┘     │      │        │  ├─ Subdomain discovery    │  │
                     │      ▼        │  ├─ Certificates           │  │
                     │ ┌────────┐    │  ├─ HTTP analysis + crawl  │  │
                     │ │Scope   │    │  ├─ IP/ASN attribution     │  │
                     │ │validator│◀───│  ├─ Tech fingerprinting    │  │
                     │ │(SSRF)  │    │  ├─ JS analysis            │  │
                     │ └────────┘    │  └─ Scoring + diff         │  │
                     │               └──────────┬─────────────────┘  │
                     │ PostgreSQL/SQLite ───────┤ Redis (optional)    │
                     └──────────────────────────┴─────────────────────┘
```

## Quick start (one-click launchers)

The easiest way to run ReconMap Pro locally with no manual setup:

**Windows:** double-click **`start.bat`** (or run it from a terminal).
**Linux / macOS:** run `./start.sh`.

The launcher will:

1. Create a Python virtual environment (first run only)
2. Install backend and frontend dependencies (first run only)
3. Build the React dashboard
4. Start the bundled demo lab on `http://localhost:8099`
5. Start the API + web UI on `http://localhost:8000`
6. Open your browser automatically

Once the UI loads, click **New scan** and target `lab.local` (the
authorized local demo). Press `Ctrl+C` in the terminal to stop.

**Windows CLI shortcut** — run a scan from a terminal without the UI:

```bat
scan.bat lab.local
scan.bat example.com --passive
scan.bat lab.local --active-subdomains
```

Requirements: Python 3.11+ (required) and Node.js 18+ (optional — needed
for the dashboard; the API, CLI and Swagger docs work without it).

## Quick start (Docker Compose — production stack)

```bash
docker compose up --build
# UI:        http://localhost:8080
# API docs:  http://localhost:8000/docs
```

This starts PostgreSQL, Redis, the FastAPI backend, an arq worker, the
React frontend (nginx) and the local demonstration lab.

## Quick start (local development, zero dependencies)

The backend defaults to SQLite and an in-process task queue so it runs with
no external services:

```bash
# Backend
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn app.main:app --reload

# Frontend (another terminal)
cd frontend
npm install
npm run dev          # http://localhost:5173 (proxies /api → :8000)
```

## Running the local demonstration lab

The `lab/` directory contains an authorized, intentionally simple target
that simulates a small company (main site, API subdomain, blog with JS
assets). It is the only target you should scan while experimenting locally.

```bash
# Terminal 1: run the lab
python lab/server.py            # listens on 0.0.0.0:8099

# Terminal 2: run the backend with private-network access enabled
# (the lab is served from 127.0.0.1 in local-dev mode)
cd backend
RECONMAP_ALLOW_PRIVATE_NETWORKS=true RECONMAP_DATABASE_URL=sqlite+aiosqlite:///./lab.db \
  uvicorn app.main:app --reload
```

Then scan `lab.local` through the UI. The lab's HTTP server uses the `Host`
header to serve the virtual subdomains, so add to `/etc/hosts`:

```
127.0.0.1 lab.local api.lab.local blog.lab.local
```

> In the Docker Compose stack the lab is reachable via network aliases
> (`lab.local`, `api.lab.local`, `blog.lab.local`); set
> `RECONMAP_ALLOW_PRIVATE_NETWORKS=true` on the backend service to scan it.

## CLI

```bash
python -m app.cli scan example.com                       # full scan
python -m app.cli scan example.com --passive             # passive only
python -m app.cli scan example.com --active-subdomains   # small wordlist
python -m app.cli list
python -m app.cli report <scan_id>
python -m app.cli policies
```

## REST API

Interactive docs: <http://localhost:8000/docs>

```bash
# Start a scan
curl -X POST http://localhost:8000/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"target":"example.com","passive_only":false}'

# Poll status
curl http://localhost:8000/api/scans/<id>

# Fetch the attack-surface graph
curl http://localhost:8000/api/scans/<id>/graph

# Generate a report
curl -X POST http://localhost:8000/api/scans/<id>/report
```

## Safety model

All network I/O flows through `app.security.scope.ScopeValidator` and
`app.recon.http_client.SafeHttpClient`, which:

1. Verify the target hostname is within the explicitly authorized scope
   (root domain and subdomains).
2. Resolve the hostname and reject any result in loopback, RFC1918,
   link-local, CGNAT, multicast, reserved or unspecified ranges.
3. **Unconditionally** block cloud metadata endpoints
   (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`, etc.).
4. Re-validate every HTTP redirect hop.
5. Apply a token-bucket rate limit per host.
6. Never submit non-GET forms, never attempt authentication, never send
   exploit payloads.

The platform's declaration of allowed/blocked activities is exposed at
`GET /api/policies` and rendered in the UI.

## Testing

```bash
cd backend
pytest -q
```

45 tests cover scope/SSRF protection, fingerprinting, scoring, diffing and
HTTP-client guardrails.

## Project layout

```
reconmap-pro/
├── backend/
│   ├── app/
│   │   ├── api/routes/      # FastAPI routers
│   │   ├── recon/           # DNS, subdomains, certs, HTTP, crawler, tech, JS, IP/ASN
│   │   ├── security/        # Scope validator, SSRF protection, rate limiter, policies
│   │   ├── services/        # Scan orchestrator, graph, scoring, diff, reports
│   │   ├── config.py
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── schemas.py
│   │   ├── workers.py
│   │   ├── cli.py
│   │   └── main.py
│   └── tests/
├── frontend/
│   └── src/
│       ├── components/
│       ├── pages/
│       ├── api/
│       ├── hooks/
│       └── types/
├── lab/                     # authorized local demo target
├── docker-compose.yml
└── README.md
```

## License

Research / portfolio project. Use responsibly and only against systems you
are explicitly authorized to test.
