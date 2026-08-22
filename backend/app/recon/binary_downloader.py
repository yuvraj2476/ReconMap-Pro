"""Manager for automatic downloading of external security tools (subfinder)."""
from __future__ import annotations

import logging
import os
import platform
import shutil
import zipfile
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Hardcoded stable version to ensure reliability and correct OS build matching.
SUBFINDER_VERSION = "2.6.6"

def get_bin_dir() -> Path:
    """Return the absolute path to the backend/bin directory."""
    # __file__ is backend/app/recon/binary_downloader.py
    # parents[2] is backend/
    bin_dir = Path(__file__).resolve().parents[2] / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    return bin_dir

def get_subfinder_path() -> Optional[str]:
    """Return the path to the subfinder binary if it exists."""
    bin_dir = get_bin_dir()
    binary_name = "subfinder.exe" if platform.system() == "Windows" else "subfinder"
    binary_path = bin_dir / binary_name
    if binary_path.exists():
        return str(binary_path)
    return None

async def download_subfinder(allow_download: bool) -> Optional[str]:
    """Download and extract subfinder binary if not already present.

    Args:
        allow_download: Boolean flag representing explicit user consent.
    """
    existing = get_subfinder_path()
    if existing:
        return existing

    if not allow_download:
        logger.info("Tool download is disabled. Skipping subfinder download.")
        return None

    bin_dir = get_bin_dir()
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Match OS/Arch for subfinder download URLs
    os_name = "windows" if "win" in system else "linux" if "linux" in system else "mac"
    arch_name = "amd64" if "64" in machine or "x86_64" in machine else "386"
    if "arm" in machine or "aarch" in machine:
        arch_name = "arm64"

    extension = "zip"
    filename = f"subfinder_{SUBFINDER_VERSION}_{os_name}_{arch_name}.{extension}"
    download_url = f"https://github.com/projectdiscovery/subfinder/releases/download/v{SUBFINDER_VERSION}/{filename}"

    logger.info("Downloading subfinder from %s ...", download_url)
    
    zip_path = bin_dir / filename
    binary_name = "subfinder.exe" if os_name == "windows" else "subfinder"
    binary_path = bin_dir / binary_name

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
            resp = await client.get(download_url)
            resp.raise_for_status()
            zip_path.write_bytes(resp.content)

        # Extract zip file
        logger.info("Extracting %s ...", filename)
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            # We want to extract just the subfinder / subfinder.exe file
            for name in zip_ref.namelist():
                if name.lower() == binary_name or name.lower().endswith("/" + binary_name):
                    with zip_ref.open(name) as source, open(binary_path, "wb") as target:
                        shutil.copyfileobj(source, target)
                    break
        
        # Clean up downloaded zip
        if zip_path.exists():
            zip_path.unlink()

        # Set execute permissions on Unix-like systems
        if os_name != "windows":
            os.chmod(binary_path, 0o755)

        logger.info("subfinder successfully installed at %s", binary_path)
        return str(binary_path)

    except Exception as exc:
        logger.error("Failed to download/install subfinder: %s", exc)
        if zip_path.exists():
            zip_path.unlink()
        if binary_path.exists():
            binary_path.unlink()
        return None
