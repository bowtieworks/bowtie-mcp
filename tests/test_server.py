"""Integration tests for MCP server tool handlers."""

from __future__ import annotations

from typing import Any

import pytest

from bowtie_mcp.client import ApiError


def decode_result(result: Any) -> Any:
    if isinstance(result, str):
        import json

        return json.loads(result)
    return result


def test_tool_metadata_exposes_structured_result_schema():
    from bowtie_mcp.server import app

    tool = next(tool for tool in app._tool_manager.list_tools() if tool.name == "list_users")
    result_schema = tool.output_schema["properties"]["result"]

    assert any(option["type"] == "object" for option in result_schema["anyOf"])


class TestReadTools:
    @pytest.mark.asyncio
    async def test_list_users(self, mock_client):
        from bowtie_mcp.server import list_users

        mock_client.list_users.return_value = {"u1": {"id": "u1", "name": "Alice"}}
        result = decode_result(await list_users())
        assert "u1" in result

    @pytest.mark.asyncio
    async def test_list_devices_with_state_filter(self, mock_client):
        from bowtie_mcp.server import list_devices

        mock_client.list_devices.return_value = {
            "devices": {
                "d1": {"id": "d1", "state": "pending"},
                "d2": {"id": "d2", "state": "accepted"},
            }
        }
        result = decode_result(await list_devices(state="pending"))
        assert "d1" in result
        assert "d2" not in result

    @pytest.mark.asyncio
    async def test_get_policy(self, mock_client):
        from bowtie_mcp.server import get_policy

        mock_client.get_policy.return_value = {
            "resources": {},
            "resource_groups": {},
            "policies": {},
        }
        result = decode_result(await get_policy())
        assert "policies" in result

    @pytest.mark.asyncio
    async def test_health_check(self, mock_client):
        from bowtie_mcp.server import health_check

        mock_client.health_check.return_value = {"status": "ok"}
        result = decode_result(await health_check())
        assert result["status"] == "ok"

    @pytest.mark.asyncio
    async def test_error_returns_structured_json(self, mock_client):
        from bowtie_mcp.server import list_users

        mock_client.list_users.side_effect = ApiError(
            500, "server error", "/users"
        )
        result = decode_result(await list_users())
        assert result["tool"] == "list_users"
        assert result["status_code"] == 500


class TestWriteToolsConfirmation:
    @pytest.mark.asyncio
    async def test_write_returns_confirmation_when_not_confirmed(self, mock_client):
        from bowtie_mcp.server import upsert_user

        result = decode_result(
            await upsert_user(name="Alice", email="alice@example.com", confirm=False)
        )
        assert result["confirmation_required"] is True
        assert result["tool"] == "upsert_user"
        mock_client.upsert_user.assert_not_called()

    @pytest.mark.asyncio
    async def test_write_executes_when_confirmed(self, mock_client):
        from bowtie_mcp.server import upsert_user

        mock_client.upsert_user.return_value = {"id": "u1", "name": "Alice"}
        result = decode_result(
            await upsert_user(name="Alice", email="alice@example.com", confirm=True)
        )
        assert result["name"] == "Alice"
        mock_client.upsert_user.assert_called_once()

    @pytest.mark.asyncio
    async def test_skip_confirmation_env_var(self, mock_client, monkeypatch):
        import bowtie_mcp.server as server_mod
        from bowtie_mcp.server import change_device_state

        monkeypatch.setattr(server_mod, "SKIP_CONFIRMATION", True)
        mock_client.change_device_state.return_value = {
            "devices": [{"id": "d1", "state": "accepted"}]
        }
        result = decode_result(
            await change_device_state(device_ids=["d1"], state="accepted", confirm=False)
        )
        assert "confirmation_required" not in result
        mock_client.change_device_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_change_device_state_validates_state(self, mock_client):
        from bowtie_mcp.server import change_device_state

        result = decode_result(
            await change_device_state(
                device_ids=["d1"], state="invalid", confirm=True
            )
        )
        assert "error" in result

    @pytest.mark.asyncio
    async def test_upsert_policy_simple_predicate(self, mock_client):
        from bowtie_mcp.server import upsert_policy

        mock_client.upsert_policy.return_value = {
            "id": "p1",
            "action": "Accept",
        }
        result = decode_result(
            await upsert_policy(
                source_predicate="AuthenticatedUser",
                dest_group_id="rg1",
                action="Accept",
                confirm=True,
            )
        )
        assert result["action"] == "Accept"
        call_data = mock_client.upsert_policy.call_args[0][0]
        assert call_data["source"]["predicate"] == "AuthenticatedUser"

    @pytest.mark.asyncio
    async def test_upsert_policy_group_predicate(self, mock_client):
        from bowtie_mcp.server import upsert_policy

        mock_client.upsert_policy.return_value = {"id": "p1"}
        await upsert_policy(
            source_predicate="InUserGroup",
            source_value="group-uuid",
            dest_group_id="rg1",
            action="Accept",
            confirm=True,
        )
        call_data = mock_client.upsert_policy.call_args[0][0]
        assert call_data["source"]["predicate"] == {"InUserGroup": "group-uuid"}

    @pytest.mark.asyncio
    async def test_upsert_policy_requires_source_value(self, mock_client):
        from bowtie_mcp.server import upsert_policy

        result = decode_result(
            await upsert_policy(
                source_predicate="InDeviceGroup",
                dest_group_id="rg1",
                action="Accept",
                confirm=True,
            )
        )
        assert "error" in result

    @pytest.mark.asyncio
    async def test_upsert_resource_port_range(self, mock_client):
        from bowtie_mcp.server import upsert_resource

        mock_client.upsert_resource.return_value = {"id": "r1"}
        result = decode_result(
            await upsert_resource(
                name="Web",
                protocol="tcp",
                location_type="cidr",
                location_value="10.0.0.0/24",
                port_start=80,
                port_end=443,
                confirm=True,
            )
        )
        call_data = mock_client.upsert_resource.call_args[0][0]
        assert call_data["ports"] == {"range": [80, 443]}

    @pytest.mark.asyncio
    async def test_upsert_resource_port_collection(self, mock_client):
        from bowtie_mcp.server import upsert_resource

        mock_client.upsert_resource.return_value = {"id": "r1"}
        await upsert_resource(
            name="Web",
            protocol="tcp",
            location_type="ip",
            location_value="10.0.0.1",
            ports=[80, 443, 8080],
            confirm=True,
        )
        call_data = mock_client.upsert_resource.call_args[0][0]
        assert call_data["ports"] == {"collection": {"ports": [80, 443, 8080]}}


class TestDnsTools:
    @pytest.mark.asyncio
    async def test_upsert_dns_config_confirmation(self, mock_client):
        from bowtie_mcp.server import upsert_dns_config

        result = decode_result(
            await upsert_dns_config(
                name="internal.example.com",
                server_addrs=["10.0.0.53"],
                confirm=False,
            )
        )
        assert result["confirmation_required"] is True
        assert result["details"]["name"] == "internal.example.com"
        assert result["details"]["strategy_resolver"] == "overlay"

    @pytest.mark.asyncio
    async def test_upsert_dns_config_executes(self, mock_client):
        from bowtie_mcp.server import upsert_dns_config

        mock_client.upsert_dns_config.return_value = {"id": "dns1"}
        result = decode_result(
            await upsert_dns_config(
                name="internal.example.com",
                server_addrs=["10.0.0.53", "10.0.0.54"],
                strategy_resolver="exclusive",
                is_log=True,
                confirm=True,
            )
        )
        call_data = mock_client.upsert_dns_config.call_args[0][0]
        assert call_data["strategy_resolver"] == "exclusive"
        assert call_data["is_log"] is True
        assert len(call_data["servers"]) == 2
