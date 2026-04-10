"""Shared test fixtures for Bowtie MCP tests."""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

# Set required env vars before importing anything from the package
os.environ.setdefault("BOWTIE_HOST", "https://bt0.test.example.com")
os.environ.setdefault("BOWTIE_API_KEY_ID", "test-key-id")
os.environ.setdefault("BOWTIE_API_KEY_SECRET", "bts1_test-secret")


@pytest.fixture(autouse=True)
def _reset_client():
    """Reset the global client between tests."""
    import bowtie_mcp.server as server_mod

    server_mod._client = None
    yield
    server_mod._client = None


@pytest.fixture()
def mock_client():
    """Return a mock BowtieClient whose methods are all AsyncMocks."""
    from bowtie_mcp.client import BowtieClient

    mock = AsyncMock(spec=BowtieClient)
    with patch("bowtie_mcp.server._get_client", return_value=mock):
        yield mock
