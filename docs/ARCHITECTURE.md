# ReconMap Pro Architecture

## Core Pipelines
1. **DNS & Subdomain Recon**: Queries Certificate Transparency logs and subfinder APIs.
2. **Exposed Codebase Scanner**: Verifies `.git/config` signatures and project backup archives.
3. **Fingerprinting**: Identifies 50+ technology stacks and security header configurations.
4. **Attack-Surface Graph** Renders cytoscape force-directed graph with confidence scoring.