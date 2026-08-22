# ReconMap Pro

ReconMap Pro is an authorization-first attack surface mapper and intelligence tool. It maps any in-scope target domain into an interactive infrastructure graph showing subdomains, DNS records, IPs, hosting details, TLS certs, HTTP endpoints, and frontend/backend tech stacks.

**This tool is built to be safe by default.** All active checks require explicit scope validation. It unconditionally blocks loopback, private ranges, and cloud metadata IPs to protect against SSRF.

---

## What It Does

- **Advanced Subdomain Recon**: Scrapes crt.sh (Certificate Transparency) and runs passive subdomain collection. Integrates with **Subfinder** (automatically downloaded on demand) and configures Shodan/Censys/VirusTotal API keys.
- **Exposed Codebase Scanner**: Probes for exposed source control folders (`.git/config`, `.git/HEAD`) and codebase zip backups (`backup.zip`, `code.zip`, etc.). Verifies headers/signatures to prevent false positives and estimates download size.
- **Service & Tech Fingerprinting**: Fingerprints over 50+ common technologies, web servers, and libraries. Checks security headers (HSTS, CSP, X-Frame-Options) and cookie safety flags.
- **Web Crawler & JS Analyzer**: Crawls internal links up to user-defined page and depth limits. Extracts endpoints, URLs, and secrets (API keys, JWTs) from client-side JS bundles.
- **Interactive Visualizer**: Generates an interactive force-directed graph of all assets and their relationships. Clicking assets shows confidence levels, evidence, and direct action triggers.
- **Reports**: Compiles professional HTML reports detailing all assets, attention scores, and CWE-mapped security observations.

---

## Setup & Quick Start

### ⚡ Launcher (Windows)
Double-click **`start.bat`**. 
The script will bootstrap a Python virtual environment, install dependencies, build the React frontend, and launch the web UI at `http://localhost:8000`.

### ⚡ Launcher (Linux / macOS)
Run:
```bash
./start.sh
```

### 🐳 Docker Compose
Spin up the PostgreSQL, Redis, FastAPI, and React stack:
```bash
docker compose up --build
```

---

## Advanced Configurations (via Environment)

Configure environment variables in `backend/.env` or export them directly:

| Variable | Description |
|---|---|
| `RECONMAP_ALLOW_TOOL_DOWNLOAD` | Set to `true` to allow auto-downloading `subfinder` |
| `RECONMAP_SUBFINDER_SHODAN_API` | Shodan API key for subdomain resolution |
| `RECONMAP_SUBFINDER_VIRUSTOTAL_API` | VirusTotal API key |
| `RECONMAP_SUBFINDER_CENSYS_API` | Censys API credentials (`ID:Secret`) |
| `RECONMAP_ALLOW_PRIVATE_NETWORKS` | Allows scanning local/private targets |
| `RECONMAP_DATABASE_URL` | SQLAlchemy connection string |

---

## Project Structure

- `/backend` - FastAPI async api, task workers, SQLite database, and scanners.
- `/frontend` - React, TypeScript, Tailwind, Cytoscape.js dashboard.
- `start.bat` - Bootstrapper for local execution on Windows.
- `scan.bat` - CLI scanner utility for quick domain audits.
