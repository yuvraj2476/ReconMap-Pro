"""Tests for the exposed codebase scanner."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock
import pytest

from app.recon.exposed_source import check_exposed_code
from app.recon.http_client import FetchResult
from app.security.scope import ScopeValidator

@pytest.mark.asyncio
async def test_check_exposed_code_finds_git():
    # Setup mock SafeHttpClient
    client = MagicMock()
    
    # Mock result for .git/config
    mock_git_result = MagicMock(spec=FetchResult)
    mock_git_result.status_code = 200
    mock_git_result.text = "[core]\nrepositoryformatversion=0"
    mock_git_result.content = b"[core]\nrepositoryformatversion=0"
    mock_git_result.headers = {"content-length": "42"}
    mock_git_result.final_url = "http://example.com/.git/config"
    mock_git_result.ip = "93.184.216.34"

    # AsyncMock for get method
    async_get = AsyncMock()
    client.get = async_get
    
    async_get.return_value = mock_git_result

    # Scope validator permitting example.com
    validator = ScopeValidator.for_target("example.com")

    # Run check
    found = await check_exposed_code("http://example.com/", client, validator)

    # Asserts
    assert len(found) > 0
    git_cand = next(f for f in found if f["path"] == ".git/config")
    assert git_cand["code_type"] == "Git Repository"
    assert git_cand["size_bytes"] == 42
    assert git_cand["size_human"] == "42 B"


@pytest.mark.asyncio
async def test_check_exposed_code_finds_zip():
    client = MagicMock()
    
    # Mock result for backup.zip (PK zip header signature)
    mock_zip_result = MagicMock(spec=FetchResult)
    mock_zip_result.status_code = 200
    mock_zip_result.text = ""
    mock_zip_result.content = b"PK\x03\x04\x14\x00\x08\x00\x08\x00"
    mock_zip_result.headers = {"content-length": "1048576"}
    mock_zip_result.final_url = "http://example.com/backup.zip"
    mock_zip_result.ip = "93.184.216.34"

    async_get = AsyncMock()
    client.get = async_get
    async_get.return_value = mock_zip_result

    validator = ScopeValidator.for_target("example.com")

    found = await check_exposed_code("http://example.com/", client, validator)

    assert len(found) > 0
    zip_cand = next(f for f in found if f["path"] == "backup.zip")
    assert zip_cand["code_type"] == "Zip Backup"
    assert zip_cand["size_bytes"] == 1048576
    assert zip_cand["size_human"] == "1.0 MB"


@pytest.mark.asyncio
async def test_check_exposed_code_ignores_invalid_content():
    client = MagicMock()
    
    # Mock result for .git/config returning normal HTML (e.g. customized 404 page)
    mock_html_result = MagicMock(spec=FetchResult)
    mock_html_result.status_code = 200
    mock_html_result.text = "<html>Page Not Found</html>"
    mock_html_result.content = b"<html>Page Not Found</html>"
    mock_html_result.headers = {}
    mock_html_result.final_url = "http://example.com/.git/config"
    mock_html_result.ip = "93.184.216.34"

    async_get = AsyncMock()
    client.get = async_get
    async_get.return_value = mock_html_result

    validator = ScopeValidator.for_target("example.com")

    found = await check_exposed_code("http://example.com/", client, validator)

    assert len(found) == 0
