"""Tests for the automatic tool downloader and config generator."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from app.config import Settings
from app.recon.binary_downloader import download_subfinder, get_bin_dir
from app.recon.provider_config import generate_subfinder_config

@pytest.mark.asyncio
async def test_subfinder_download_rejected_without_consent():
    # If consent is False, download should return None immediately
    binary_path = await download_subfinder(allow_download=False)
    assert binary_path is None

def test_generate_subfinder_config():
    settings = Settings(
        subfinder_shodan_api="test_shodan_key",
        subfinder_virustotal_api="test_virustotal_key",
        subfinder_censys_api="test_censys_key"
    )
    
    config_path = generate_subfinder_config(settings)
    assert Path(config_path).exists()
    
    # Read back config file to check format
    with open(config_path, "r") as f:
        import yaml
        data = yaml.safe_load(f)
        assert data["shodan"] == ["test_shodan_key"]
        assert data["virustotal"] == ["test_virustotal_key"]
        assert data["censys"] == ["test_censys_key"]

    # Cleanup generated config file
    if Path(config_path).exists():
        Path(config_path).unlink()
