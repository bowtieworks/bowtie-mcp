"""Thin async HTTP client wrapping the Bowtie Control Plane REST API."""

from __future__ import annotations

import os
import uuid
from typing import Any

import httpx

API_PREFIX = "/-net/api/v0"


class AuthError(Exception):
    """Raised when authentication fails or a session expires."""


class ApiError(Exception):
    """Raised on non-2xx responses from the Bowtie API."""

    def __init__(self, status_code: int, detail: str, url: str) -> None:
        self.status_code = status_code
        self.detail = detail
        self.url = url
        super().__init__(f"HTTP {status_code} from {url}: {detail}")


class BowtieClient:
    """Async HTTP client for the Bowtie control plane.

    Supports two auth modes:
      1. API key (BOWTIE_API_KEY_ID + BOWTIE_API_KEY_SECRET) — sent as HTTP Basic auth.
      2. Password (BOWTIE_USERNAME + BOWTIE_PASSWORD) — logs in to obtain a session cookie.
    """

    def __init__(self) -> None:
        host = os.environ.get("BOWTIE_HOST", "").rstrip("/")
        if not host:
            raise ValueError("BOWTIE_HOST environment variable is required")

        self._base = host
        self._api_key_id = os.environ.get("BOWTIE_API_KEY_ID")
        self._api_key_secret = os.environ.get("BOWTIE_API_KEY_SECRET")
        self._username = os.environ.get("BOWTIE_USERNAME")
        self._password = os.environ.get("BOWTIE_PASSWORD")
        self._client: httpx.AsyncClient | None = None
        self._authenticated = False

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._base,
                timeout=30.0,
                follow_redirects=False,
            )
        if not self._authenticated:
            await self._authenticate()
        return self._client

    async def _authenticate(self) -> None:
        assert self._client is not None
        if self._api_key_id and self._api_key_secret:
            self._client.auth = httpx.BasicAuth(self._api_key_id, self._api_key_secret)
            self._authenticated = True
        elif self._username and self._password:
            resp = await self._client.post(
                f"{API_PREFIX}/user/login",
                json={
                    "email_or_username": self._username,
                    "password": self._password,
                },
            )
            if resp.status_code not in (200, 301, 302, 303):
                raise AuthError(f"Login failed: HTTP {resp.status_code}")
            self._authenticated = True
        else:
            raise AuthError(
                "Provide BOWTIE_API_KEY_ID + BOWTIE_API_KEY_SECRET, "
                "or BOWTIE_USERNAME + BOWTIE_PASSWORD"
            )

    async def _re_authenticate(self) -> None:
        self._authenticated = False
        await self._authenticate()

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any | None = None,
        params: dict[str, str] | None = None,
    ) -> Any:
        client = await self._ensure_client()
        url = f"{API_PREFIX}{path}"
        resp = await client.request(method, url, json=json, params=params)

        # Handle auth expiry — retry once after re-authenticating
        if resp.status_code == 401:
            await self._re_authenticate()
            client = await self._ensure_client()
            resp = await client.request(method, url, json=json, params=params)

        if resp.status_code == 204:
            return {"ok": True}

        if resp.status_code >= 400:
            try:
                detail = resp.text
            except Exception:
                detail = resp.reason_phrase or "Unknown error"
            raise ApiError(resp.status_code, detail, url)

        if not resp.content:
            return {"ok": True}

        return resp.json()

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    async def health_check(self) -> dict:
        """Check that the controller is up."""
        client = await self._ensure_client()
        resp = await client.get(f"{API_PREFIX}/ok")
        return {"status": "ok" if resp.status_code == 200 else "error"}

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    async def list_users(self) -> dict:
        return await self._request("GET", "/users")

    async def get_user(self, user_id: str) -> dict:
        return await self._request("GET", f"/user/{user_id}")

    async def upsert_user(self, data: dict) -> dict:
        return await self._request("POST", "/user/upsert", json=data)

    async def delete_user(self, user_id: str) -> dict:
        return await self._request("DELETE", f"/user/{user_id}")

    async def get_current_user(self) -> dict:
        return await self._request("POST", "/user/me")

    # ------------------------------------------------------------------
    # User Groups
    # ------------------------------------------------------------------

    async def list_user_groups(self) -> dict:
        return await self._request("GET", "/group")

    async def get_user_group(self, group_id: str) -> dict:
        return await self._request("GET", f"/group/{group_id}")

    async def list_users_in_group(self, group_id: str) -> dict:
        return await self._request("GET", f"/group/{group_id}/list")

    async def upsert_user_group(self, data: dict) -> dict:
        return await self._request("POST", "/group/upsert", json=data)

    async def add_users_to_group(self, group_id: str, users: list[dict]) -> dict:
        return await self._request(
            "POST", "/group/addusers", json={"group_id": group_id, "users": users}
        )

    async def remove_users_from_group(self, group_id: str, users: list[dict]) -> dict:
        return await self._request(
            "POST", "/group/removeusers", json={"group_id": group_id, "users": users}
        )

    async def delete_user_group(self, group_id: str) -> dict:
        return await self._request("DELETE", f"/group/{group_id}")

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    async def list_devices(self) -> dict:
        return await self._request("GET", "/device")

    async def get_device(self, device_id: str) -> dict:
        return await self._request("GET", f"/device/{device_id}")

    async def update_device(self, device_id: str, data: dict) -> dict:
        return await self._request("POST", f"/device/{device_id}", json=data)

    async def delete_device(self, device_id: str) -> dict:
        return await self._request("DELETE", f"/device/{device_id}")

    async def change_device_state(self, devices: list[dict]) -> dict:
        """Approve or reject devices. Each item: {id: uuid, state: pending|accepted|rejected}."""
        return await self._request(
            "POST", "/device/state", json={"devices": devices}
        )

    async def assign_device(self, device_id: str, user_id: str | None = None) -> dict:
        payload: dict[str, Any] = {"device_id": device_id}
        if user_id:
            payload["user_id"] = user_id
        return await self._request("POST", "/device/assign", json=payload)

    async def get_auth_decisions(self) -> dict:
        return await self._request("GET", "/device/auth_decisions")

    async def update_auth_decisions(self, decisions: list[dict]) -> dict:
        return await self._request(
            "POST", "/device/auth_decisions", json={"auth_decisions": decisions}
        )

    # ------------------------------------------------------------------
    # Device Groups
    # ------------------------------------------------------------------

    async def get_device_group(self, group_id: str) -> dict:
        return await self._request("GET", f"/device_group/{group_id}")

    async def list_devices_in_group(self, group_id: str) -> dict:
        return await self._request("GET", f"/device_group/{group_id}/list")

    async def upsert_device_group(self, data: dict) -> dict:
        return await self._request("POST", "/device_group/upsert", json=data)

    async def add_devices_to_group(
        self, group_id: str, device_ids: list[str]
    ) -> dict:
        return await self._request(
            "POST",
            "/device_group/adddevices",
            json={"group_id": group_id, "device_id": device_ids},
        )

    async def remove_devices_from_group(
        self, group_id: str, device_ids: list[str]
    ) -> dict:
        return await self._request(
            "POST",
            "/device_group/removedevices",
            json={"group_id": group_id, "device_id": device_ids},
        )

    async def delete_device_group(self, group_id: str) -> dict:
        return await self._request("DELETE", f"/device_group/{group_id}")

    # ------------------------------------------------------------------
    # Policy Engine
    # ------------------------------------------------------------------

    async def get_policy(self) -> dict:
        """Return the full policy document: resources, resource_groups, policies."""
        return await self._request("GET", "/policy")

    async def upsert_policy(self, data: dict) -> dict:
        return await self._request("POST", "/policy/upsert_policy", json=data)

    async def upsert_resource(self, data: dict) -> dict:
        return await self._request("POST", "/policy/upsert_resource", json=data)

    async def upsert_resource_group(self, data: dict) -> dict:
        return await self._request("POST", "/policy/upsert_resource_group", json=data)

    async def force_policy_refresh(self) -> dict:
        return await self._request("POST", "/policy/force_refresh")

    # ------------------------------------------------------------------
    # DNS Configuration
    # ------------------------------------------------------------------

    async def get_dns_configs(self) -> dict:
        """DNS configs are part of the organization response."""
        org = await self._request("GET", "/organization")
        return org.get("dns", {})

    async def get_dns_config(self, dns_id: str) -> dict:
        return await self._request("POST", f"/organization/dns/{dns_id}")

    async def upsert_dns_config(self, data: dict) -> dict:
        return await self._request("POST", "/organization/dns/upsert", json=data)

    async def delete_dns_config(self, dns_id: str) -> dict:
        return await self._request("DELETE", f"/organization/dns/{dns_id}")

    # ------------------------------------------------------------------
    # Organization
    # ------------------------------------------------------------------

    async def get_organization(self) -> dict:
        return await self._request("GET", "/organization")

    async def update_organization(self, data: dict) -> dict:
        return await self._request("POST", "/organization", json=data)

    async def get_org_config(self) -> dict:
        return await self._request("GET", "/organization/config")

    # ------------------------------------------------------------------
    # Sites
    # ------------------------------------------------------------------

    async def list_sites(self) -> list:
        return await self._request("GET", "/site")

    async def get_site(self, site_id: str) -> dict:
        return await self._request("GET", f"/site/{site_id}")

    async def upsert_site(self, data: dict) -> dict:
        return await self._request("POST", "/site", json=data)

    async def delete_site(self, site_id: str) -> dict:
        return await self._request("DELETE", f"/site/{site_id}")

    # ------------------------------------------------------------------
    # Collections
    # ------------------------------------------------------------------

    async def list_collections(self) -> dict:
        return await self._request("GET", "/collection")

    async def get_collection(self, collection_id: str) -> dict:
        return await self._request("GET", f"/collection/{collection_id}")

    async def upsert_collection(self, data: dict) -> dict:
        return await self._request("POST", "/collection/upsert", json=data)

    async def add_collection_members(
        self, collection_id: str, members: list[dict]
    ) -> dict:
        return await self._request(
            "POST",
            "/collection/addmember",
            json={"collection_id": collection_id, "members": members},
        )

    async def remove_collection_members(
        self, collection_id: str, member_ids: list[str]
    ) -> dict:
        return await self._request(
            "POST",
            "/collection/removemember",
            json={"collection_id": collection_id, "members": member_ids},
        )

    async def delete_collection(self, collection_id: str) -> dict:
        return await self._request("DELETE", f"/collection/{collection_id}")

    # ------------------------------------------------------------------
    # DNS Block Lists
    # ------------------------------------------------------------------

    async def list_dns_block_lists(self) -> dict:
        return await self._request("GET", "/dns_block_list/")

    async def upsert_dns_block_list(self, data: dict) -> dict:
        return await self._request("POST", "/dns_block_list/", json=data)

    async def delete_dns_block_list(self, block_list_id: str) -> dict:
        return await self._request("DELETE", f"/dns_block_list/{block_list_id}")

    # ------------------------------------------------------------------
    # Threat Categories
    # ------------------------------------------------------------------

    async def list_threat_categories(self) -> list:
        return await self._request("GET", "/threat_categories/")

    async def activate_threat_intel(self) -> list:
        return await self._request("POST", "/threat_categories/activate")

    async def deactivate_threat_intel(self) -> dict:
        return await self._request("POST", "/threat_categories/deactivate")

    async def toggle_threat_category(
        self, source_path: str, enabled: bool
    ) -> dict:
        return await self._request(
            "POST",
            "/threat_categories/toggle",
            json={"source_path": source_path, "enabled": enabled},
        )

    async def categorize_domain(self, domain: str) -> list:
        return await self._request(
            "GET", "/threat_categories/categorize", params={"domain": domain}
        )

    async def get_threat_feed_config(self) -> dict:
        return await self._request("GET", "/threat_categories/config")

    async def update_threat_feed_config(self, data: dict) -> dict:
        return await self._request("POST", "/threat_categories/config", json=data)

    # ------------------------------------------------------------------
    # API Keys
    # ------------------------------------------------------------------

    async def list_api_keys(self) -> dict:
        return await self._request("GET", "/api_keys/")

    async def upsert_api_key(self, data: dict) -> dict:
        return await self._request("POST", "/api_keys/", json=data)

    async def delete_api_key(self, api_key_id: str) -> dict:
        return await self._request("DELETE", f"/api_keys/{api_key_id}")

    async def get_current_api_key(self) -> dict:
        return await self._request("GET", "/api_keys/me")

    # ------------------------------------------------------------------
    # Controllers
    # ------------------------------------------------------------------

    async def list_controllers(self) -> list:
        return await self._request("GET", "/organization/controller")

    async def get_controller(self, controller_id: str) -> dict:
        return await self._request(
            "GET", f"/organization/controller/{controller_id}"
        )

    # ------------------------------------------------------------------
    # Route Exclusions
    # ------------------------------------------------------------------

    async def list_route_exclusions(self) -> dict:
        return await self._request("GET", "/route_exclusion")

    async def upsert_route_exclusion(self, data: dict) -> dict:
        return await self._request("POST", "/route_exclusion", json=data)

    async def delete_route_exclusion(self, exclusion_id: str) -> dict:
        return await self._request("DELETE", f"/route_exclusion/{exclusion_id}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def close(self) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None
            self._authenticated = False
