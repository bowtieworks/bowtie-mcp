"""Unit tests for BowtieClient HTTP methods."""

from __future__ import annotations

import json

import httpx
import pytest
import pytest_asyncio

from bowtie_mcp.client import ApiError, AuthError, BowtieClient


@pytest_asyncio.fixture
async def client(httpx_mock):
    """Create a BowtieClient with API key auth (no login call needed)."""
    c = BowtieClient()
    yield c
    await c.close()


# -- Auth ---------------------------------------------------------------


class TestAuth:
    @pytest.mark.asyncio
    async def test_api_key_auth_sets_basic(self, client, httpx_mock):
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/ok",
            json={"status": "ok"},
        )
        result = await client.health_check()
        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_missing_credentials_raises(self, monkeypatch):
        monkeypatch.delenv("BOWTIE_API_KEY_ID", raising=False)
        monkeypatch.delenv("BOWTIE_API_KEY_SECRET", raising=False)
        monkeypatch.delenv("BOWTIE_USERNAME", raising=False)
        monkeypatch.delenv("BOWTIE_PASSWORD", raising=False)
        c = BowtieClient()
        with pytest.raises(AuthError):
            await c.health_check()
        await c.close()


# -- Users --------------------------------------------------------------


class TestUsers:
    @pytest.mark.asyncio
    async def test_list_users(self, client, httpx_mock):
        payload = {"user-1": {"id": "user-1", "name": "Alice"}}
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/users",
            json=payload,
        )
        result = await client.list_users()
        assert "user-1" in result

    @pytest.mark.asyncio
    async def test_get_user(self, client, httpx_mock):
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/user/abc-123",
            json={"id": "abc-123", "name": "Bob"},
        )
        result = await client.get_user("abc-123")
        assert result["name"] == "Bob"

    @pytest.mark.asyncio
    async def test_upsert_user(self, client, httpx_mock):
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/user/upsert",
            json={"id": "new-user", "name": "Charlie"},
        )
        result = await client.upsert_user({"name": "Charlie"})
        assert result["name"] == "Charlie"

    @pytest.mark.asyncio
    async def test_delete_user_204(self, client, httpx_mock):
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/user/abc-123",
            status_code=204,
        )
        result = await client.delete_user("abc-123")
        assert result["ok"] is True


# -- Devices ------------------------------------------------------------


class TestDevices:
    @pytest.mark.asyncio
    async def test_list_devices(self, client, httpx_mock):
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/device",
            json={"devices": {"d1": {"id": "d1", "state": "accepted"}}},
        )
        result = await client.list_devices()
        assert "d1" in result["devices"]

    @pytest.mark.asyncio
    async def test_change_device_state(self, client, httpx_mock):
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/device/state",
            json={"devices": [{"id": "d1", "state": "accepted"}]},
        )
        result = await client.change_device_state(
            [{"id": "d1", "state": "accepted"}]
        )
        assert result["devices"][0]["state"] == "accepted"


# -- Policy -------------------------------------------------------------


class TestPolicy:
    @pytest.mark.asyncio
    async def test_get_policy(self, client, httpx_mock):
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/policy",
            json={"resources": {}, "resource_groups": {}, "policies": {}},
        )
        result = await client.get_policy()
        assert "policies" in result

    @pytest.mark.asyncio
    async def test_upsert_policy(self, client, httpx_mock):
        policy = {"id": "p1", "source": {}, "dest": "rg1", "action": "Accept"}
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/policy/upsert_policy",
            json=policy,
        )
        result = await client.upsert_policy(policy)
        assert result["id"] == "p1"


# -- Error handling -----------------------------------------------------


class TestErrors:
    @pytest.mark.asyncio
    async def test_404_raises_api_error(self, client, httpx_mock):
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/user/nonexistent",
            status_code=404,
            text="Not Found",
        )
        with pytest.raises(ApiError) as exc:
            await client.get_user("nonexistent")
        assert exc.value.status_code == 404

    @pytest.mark.asyncio
    async def test_500_raises_api_error(self, client, httpx_mock):
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/users",
            status_code=500,
            text="Internal Server Error",
        )
        with pytest.raises(ApiError) as exc:
            await client.list_users()
        assert exc.value.status_code == 500

    @pytest.mark.asyncio
    async def test_401_retries_auth(self, client, httpx_mock):
        # First call returns 401, second should succeed after re-auth
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/users",
            status_code=401,
        )
        httpx_mock.add_response(
            url="https://bt0.test.example.com/-net/api/v0/users",
            json={"user-1": {"id": "user-1"}},
        )
        result = await client.list_users()
        assert "user-1" in result
