"""Generates the provider config file for subfinder API keys dynamically."""
from __future__ import annotations

import logging
from pathlib import Path
import yaml

from app.config import Settings
from app.recon.binary_downloader import get_bin_dir

logger = logging.getLogger(__name__)

def generate_subfinder_config(settings: Settings) -> str:
    """Generate subfinder provider-config.yaml file from settings.

    Returns the absolute path to the generated config file.
    """
    config_data = {}

    if settings.subfinder_shodan_api:
        config_data["shodan"] = [settings.subfinder_shodan_api]

    if settings.subfinder_virustotal_api:
        config_data["virustotal"] = [settings.subfinder_virustotal_api]

    if settings.subfinder_censys_api:
        # Censys expects a list of api_id:api_secret
        config_data["censys"] = [settings.subfinder_censys_api]

    bin_dir = get_bin_dir()
    config_path = bin_dir / "provider-config.yaml"

    try:
        # Write config YAML
        with open(config_path, "w") as f:
            yaml.safe_dump(config_data, f, default_flow_style=False)
        logger.info("Successfully generated subfinder provider config at %s", config_path)
    except Exception as exc:
        logger.error("Failed to write subfinder provider config: %s", exc)

    return str(config_path)
