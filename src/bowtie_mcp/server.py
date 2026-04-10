"""MCP server exposing Bowtie control plane operations as tools and prompts."""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

from bowtie_mcp.client import ApiError, BowtieClient

app = FastMCP(
    "Bowtie MCP Server",
    instructions="Manage your Bowtie zero-trust network cluster: policies, devices, DNS, users, and more.",
)

_client: BowtieClient | None = None
SKIP_CONFIRMATION = os.environ.get("BOWTIE_MCP_SKIP_CONFIRMATION", "").lower() == "true"


def _get_client() -> BowtieClient:
    global _client
    if _client is None:
        _client = BowtieClient()
    return _client


def _ok(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def _error(tool: str, err: Exception) -> str:
    body: dict[str, Any] = {"tool": tool, "error": str(err)}
    if isinstance(err, ApiError):
        body["status_code"] = err.status_code
        body["detail"] = err.detail
    return json.dumps(body, indent=2)


def _confirmation_required(tool: str, action: str, details: dict) -> str:
    return json.dumps(
        {
            "confirmation_required": True,
            "tool": tool,
            "action": action,
            "details": details,
            "message": f"Call this tool again with confirm=true to execute: {action}",
        },
        indent=2,
        default=str,
    )


# ======================================================================
# Read Tools
# ======================================================================


@app.tool()
async def health_check() -> str:
    """Check that the Bowtie controller is reachable and responding.
    Use this first to verify connectivity before running other tools."""
    try:
        result = await _get_client().health_check()
        return _ok(result)
    except Exception as e:
        return _error("health_check", e)


# -- Users -------------------------------------------------------------


@app.tool()
async def list_users() -> str:
    """List all users in the Bowtie organization.
    Returns a map of user IDs to user objects with name, email, role, and status.
    Use this to find user IDs needed by other tools."""
    try:
        return _ok(await _get_client().list_users())
    except Exception as e:
        return _error("list_users", e)


@app.tool()
async def get_user(user_id: str) -> str:
    """Get details for a specific user by their UUID.
    Returns name, email, role (Owner/FullAdministrator/LimitedAdministrator/User), status, and permissions."""
    try:
        return _ok(await _get_client().get_user(user_id))
    except Exception as e:
        return _error("get_user", e)


@app.tool()
async def get_current_user() -> str:
    """Get information about the currently authenticated user and their devices.
    Useful for verifying who you're acting as."""
    try:
        return _ok(await _get_client().get_current_user())
    except Exception as e:
        return _error("get_current_user", e)


# -- User Groups -------------------------------------------------------


@app.tool()
async def list_user_groups() -> str:
    """List all user groups. Returns a map of group IDs to group objects.
    User groups are used in policy source predicates to control which users can access resources."""
    try:
        return _ok(await _get_client().list_user_groups())
    except Exception as e:
        return _error("list_user_groups", e)


@app.tool()
async def get_user_group(group_id: str) -> str:
    """Get a user group by ID, including its name and metadata."""
    try:
        return _ok(await _get_client().get_user_group(group_id))
    except Exception as e:
        return _error("get_user_group", e)


@app.tool()
async def list_users_in_group(group_id: str) -> str:
    """List all user IDs that are members of a specific user group."""
    try:
        return _ok(await _get_client().list_users_in_group(group_id))
    except Exception as e:
        return _error("list_users_in_group", e)


# -- Devices -----------------------------------------------------------


@app.tool()
async def list_devices(state: str | None = None) -> str:
    """List all devices in the Bowtie organization.
    Optionally filter by state: 'pending', 'accepted', or 'rejected'.
    Returns device name, OS, type, assigned user, connection status, and more.
    Use this to find devices awaiting approval (state='pending')."""
    try:
        result = await _get_client().list_devices()
        devices = result.get("devices", result)
        if state:
            devices = {
                did: dev
                for did, dev in devices.items()
                if dev.get("state") == state
            }
        return _ok(devices)
    except Exception as e:
        return _error("list_devices", e)


@app.tool()
async def get_device(device_id: str) -> str:
    """Get full details for a specific device including its state, assigned user,
    OS, last seen time, IPv4/IPv6 addresses, and posture information."""
    try:
        return _ok(await _get_client().get_device(device_id))
    except Exception as e:
        return _error("get_device", e)


@app.tool()
async def get_auth_decisions() -> str:
    """List pre-configured device auth decisions (pre-approvals or pre-rejections by serial number).
    Useful for MDM workflows where devices are approved before they first check in."""
    try:
        return _ok(await _get_client().get_auth_decisions())
    except Exception as e:
        return _error("get_auth_decisions", e)


# -- Device Groups -----------------------------------------------------


@app.tool()
async def get_device_group(group_id: str) -> str:
    """Get a device group by ID. Device groups are used in policy source predicates
    to control which devices can access resources."""
    try:
        return _ok(await _get_client().get_device_group(group_id))
    except Exception as e:
        return _error("get_device_group", e)


@app.tool()
async def list_devices_in_group(group_id: str) -> str:
    """List all devices that are members of a specific device group."""
    try:
        return _ok(await _get_client().list_devices_in_group(group_id))
    except Exception as e:
        return _error("list_devices_in_group", e)


# -- Policy Engine -----------------------------------------------------


@app.tool()
async def get_policy() -> str:
    """Get the complete network policy document. Returns three sections:
    - resources: network objects (IP/CIDR/DNS targets with protocol and ports)
    - resource_groups: named groups of resources used as policy destinations
    - policies: rules mapping source (who) to destination (what) with an action (Accept/Reject/Drop)

    This is the core of Bowtie's zero-trust model. Read this first when auditing or troubleshooting access."""
    try:
        return _ok(await _get_client().get_policy())
    except Exception as e:
        return _error("get_policy", e)


# -- DNS ---------------------------------------------------------------


@app.tool()
async def list_dns_configs() -> str:
    """List all DNS configurations. DNS configs define how Bowtie resolves
    internal domain names, including upstream servers, DNS64 strategy,
    resolver strategy (overlay/exclusive/drop), and site bindings."""
    try:
        return _ok(await _get_client().get_dns_configs())
    except Exception as e:
        return _error("list_dns_configs", e)


@app.tool()
async def get_dns_config(dns_id: str) -> str:
    """Get a specific DNS configuration by ID."""
    try:
        return _ok(await _get_client().get_dns_config(dns_id))
    except Exception as e:
        return _error("get_dns_config", e)


# -- Organization ------------------------------------------------------


@app.tool()
async def get_organization() -> str:
    """Get organization details including name, domain, DNS configs, IPv6 ranges, and sites.
    This is the top-level view of your Bowtie deployment."""
    try:
        return _ok(await _get_client().get_organization())
    except Exception as e:
        return _error("get_organization", e)


@app.tool()
async def get_org_config() -> str:
    """Get the organization configuration including device approval settings,
    session timeouts, telemetry preferences, version strategy, and security settings."""
    try:
        return _ok(await _get_client().get_org_config())
    except Exception as e:
        return _error("get_org_config", e)


# -- Sites -------------------------------------------------------------


@app.tool()
async def list_sites() -> str:
    """List all sites. A site represents a physical or virtual location (e.g., an office or VPC)
    with its own controllers and routable IP ranges."""
    try:
        return _ok(await _get_client().list_sites())
    except Exception as e:
        return _error("list_sites", e)


@app.tool()
async def get_site(site_id: str) -> str:
    """Get details for a specific site by ID."""
    try:
        return _ok(await _get_client().get_site(site_id))
    except Exception as e:
        return _error("get_site", e)


# -- Collections -------------------------------------------------------


@app.tool()
async def list_collections() -> str:
    """List all collections. Collections are named groups of network locations (IPs, CIDRs, DNS names)
    that can be referenced by resources, route exclusions, and other objects."""
    try:
        return _ok(await _get_client().list_collections())
    except Exception as e:
        return _error("list_collections", e)


@app.tool()
async def get_collection(collection_id: str) -> str:
    """Get a collection by ID, including all its members (network locations)."""
    try:
        return _ok(await _get_client().get_collection(collection_id))
    except Exception as e:
        return _error("get_collection", e)


# -- DNS Block Lists ---------------------------------------------------


@app.tool()
async def list_dns_block_lists() -> str:
    """List all DNS block lists configured in the organization.
    Block lists prevent resolution of known-bad domains."""
    try:
        return _ok(await _get_client().list_dns_block_lists())
    except Exception as e:
        return _error("list_dns_block_lists", e)


# -- Threat Categories -------------------------------------------------


@app.tool()
async def list_threat_categories() -> str:
    """List all threat intelligence categories with their enabled/disabled state.
    Categories group domains by threat type (malware, phishing, etc.)."""
    try:
        return _ok(await _get_client().list_threat_categories())
    except Exception as e:
        return _error("list_threat_categories", e)


@app.tool()
async def categorize_domain(domain: str) -> str:
    """Check which threat categories a domain belongs to.
    Walks parent domains, so sub.malware.example.com also matches example.com."""
    try:
        return _ok(await _get_client().categorize_domain(domain))
    except Exception as e:
        return _error("categorize_domain", e)


@app.tool()
async def get_threat_feed_config() -> str:
    """Get the current threat feed configuration including sync interval,
    last sync status, and whether block event logging is enabled."""
    try:
        return _ok(await _get_client().get_threat_feed_config())
    except Exception as e:
        return _error("get_threat_feed_config", e)


# -- API Keys ----------------------------------------------------------


@app.tool()
async def list_api_keys() -> str:
    """List all API keys in the organization. Shows key name, permissions,
    creation date, and last used info."""
    try:
        return _ok(await _get_client().list_api_keys())
    except Exception as e:
        return _error("list_api_keys", e)


# -- Controllers -------------------------------------------------------


@app.tool()
async def list_controllers() -> str:
    """List all controllers in the Bowtie cluster. Controllers are the
    enforcement points that handle WireGuard tunnels, DNS, and policy evaluation."""
    try:
        return _ok(await _get_client().list_controllers())
    except Exception as e:
        return _error("list_controllers", e)


@app.tool()
async def get_controller(controller_id: str) -> str:
    """Get details for a specific controller including its status, public address,
    version, features, and site assignment."""
    try:
        return _ok(await _get_client().get_controller(controller_id))
    except Exception as e:
        return _error("get_controller", e)


# -- Route Exclusions --------------------------------------------------


@app.tool()
async def list_route_exclusions() -> str:
    """List all route exclusions. Route exclusions define CIDRs that should
    bypass the Bowtie tunnel, typically for local network or split-tunnel scenarios."""
    try:
        return _ok(await _get_client().list_route_exclusions())
    except Exception as e:
        return _error("list_route_exclusions", e)


# ======================================================================
# Write Tools (require confirmation)
# ======================================================================


def _needs_confirmation(confirm: bool) -> bool:
    return not confirm and not SKIP_CONFIRMATION


# -- User Writes -------------------------------------------------------


@app.tool()
async def upsert_user(
    name: str,
    email: str | None = None,
    role: str | None = None,
    status: str | None = None,
    user_id: str | None = None,
    username: str | None = None,
    confirm: bool = False,
) -> str:
    """Create or update a user. Provide user_id to update an existing user.

    Args:
        name: The user's display name.
        email: Email address (used for login with password auth).
        role: One of Owner, FullAdministrator, LimitedAdministrator, User.
        status: One of Active, Disabled.
        user_id: UUID to update an existing user; omit to create a new one.
        username: Optional login username.
        confirm: Set to true to execute the change. When false, returns a preview.
    """
    data: dict[str, Any] = {"name": name}
    if user_id:
        data["id"] = user_id
    else:
        data["id"] = str(uuid.uuid4())
    if email:
        data["email"] = email
    if username:
        data["username"] = username
    if role:
        data["role"] = role
    if status:
        data["status"] = status

    action = "update user" if user_id else "create user"
    if _needs_confirmation(confirm):
        return _confirmation_required("upsert_user", action, data)
    try:
        return _ok(await _get_client().upsert_user(data))
    except Exception as e:
        return _error("upsert_user", e)


@app.tool()
async def delete_user(user_id: str, confirm: bool = False) -> str:
    """Delete a user by ID. The user must be Disabled first.
    Only Owner or FullAdministrator roles can delete users.

    Args:
        user_id: UUID of the user to delete.
        confirm: Set to true to execute the deletion.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "delete_user", "delete user", {"user_id": user_id}
        )
    try:
        return _ok(await _get_client().delete_user(user_id))
    except Exception as e:
        return _error("delete_user", e)


# -- User Group Writes -------------------------------------------------


@app.tool()
async def upsert_user_group(
    name: str,
    group_id: str | None = None,
    description: str | None = None,
    confirm: bool = False,
) -> str:
    """Create or update a user group. User groups are referenced in policy source
    predicates to control access by group membership.

    Args:
        name: Human-readable group name.
        group_id: UUID to update an existing group; omit to create a new one.
        description: Optional group description.
        confirm: Set to true to execute.
    """
    data: dict[str, Any] = {"name": name}
    if group_id:
        data["id"] = group_id
    if description:
        data["description"] = description

    action = "update user group" if group_id else "create user group"
    if _needs_confirmation(confirm):
        return _confirmation_required("upsert_user_group", action, data)
    try:
        return _ok(await _get_client().upsert_user_group(data))
    except Exception as e:
        return _error("upsert_user_group", e)


@app.tool()
async def add_users_to_group(
    group_id: str, user_ids: list[str], confirm: bool = False
) -> str:
    """Add users to a user group by their UUIDs.

    Args:
        group_id: The group to add users to.
        user_ids: List of user UUIDs to add.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "add_users_to_group",
            "add users to group",
            {"group_id": group_id, "user_ids": user_ids},
        )
    try:
        users = [{"id": uid} for uid in user_ids]
        return _ok(await _get_client().add_users_to_group(group_id, users))
    except Exception as e:
        return _error("add_users_to_group", e)


@app.tool()
async def remove_users_from_group(
    group_id: str, user_ids: list[str], confirm: bool = False
) -> str:
    """Remove users from a user group.

    Args:
        group_id: The group to remove users from.
        user_ids: List of user UUIDs to remove.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "remove_users_from_group",
            "remove users from group",
            {"group_id": group_id, "user_ids": user_ids},
        )
    try:
        users = [{"id": uid} for uid in user_ids]
        return _ok(await _get_client().remove_users_from_group(group_id, users))
    except Exception as e:
        return _error("remove_users_from_group", e)


@app.tool()
async def delete_user_group(group_id: str, confirm: bool = False) -> str:
    """Delete a user group. Any policies referencing this group will need to be updated.

    Args:
        group_id: UUID of the group to delete.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "delete_user_group", "delete user group", {"group_id": group_id}
        )
    try:
        return _ok(await _get_client().delete_user_group(group_id))
    except Exception as e:
        return _error("delete_user_group", e)


# -- Device Writes -----------------------------------------------------


@app.tool()
async def change_device_state(
    device_ids: list[str], state: str, confirm: bool = False
) -> str:
    """Approve or reject one or more devices. This is the primary way to onboard
    or block devices.

    Args:
        device_ids: List of device UUIDs to change.
        state: Target state — 'accepted' to approve, 'rejected' to block.
        confirm: Set to true to execute.
    """
    if state not in ("accepted", "rejected", "pending"):
        return _error(
            "change_device_state",
            ValueError(f"state must be accepted, rejected, or pending; got '{state}'"),
        )
    devices = [{"id": did, "state": state} for did in device_ids]
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "change_device_state",
            f"set {len(devices)} device(s) to '{state}'",
            {"devices": devices},
        )
    try:
        return _ok(await _get_client().change_device_state(devices))
    except Exception as e:
        return _error("change_device_state", e)


@app.tool()
async def delete_device(device_id: str, confirm: bool = False) -> str:
    """Delete a rejected device for cleanup after decommissioning.
    The device must be in 'rejected' state first.

    Args:
        device_id: UUID of the device to delete.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "delete_device", "delete device", {"device_id": device_id}
        )
    try:
        return _ok(await _get_client().delete_device(device_id))
    except Exception as e:
        return _error("delete_device", e)


@app.tool()
async def assign_device(
    device_id: str, user_id: str | None = None, confirm: bool = False
) -> str:
    """Assign or reassign a device to a user. This normally happens at authentication
    time, but admins can override it here.

    Args:
        device_id: The device to assign.
        user_id: The user UUID to assign to. Omit to unassign.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "assign_device",
            "assign device to user",
            {"device_id": device_id, "user_id": user_id},
        )
    try:
        return _ok(await _get_client().assign_device(device_id, user_id))
    except Exception as e:
        return _error("assign_device", e)


@app.tool()
async def update_auth_decisions(
    decisions: list[dict], confirm: bool = False
) -> str:
    """Create or update device auth decisions (pre-approve or pre-reject by serial number).
    Each decision needs: serial (string), enforce_state ('accepted'/'rejected'/'retain').

    Use this for MDM integration — approve devices by serial before they check in.

    Args:
        decisions: List of {serial, enforce_state} dicts. Optionally include device_id.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "update_auth_decisions",
            f"upsert {len(decisions)} auth decision(s)",
            {"decisions": decisions},
        )
    try:
        return _ok(await _get_client().update_auth_decisions(decisions))
    except Exception as e:
        return _error("update_auth_decisions", e)


# -- Device Group Writes -----------------------------------------------


@app.tool()
async def upsert_device_group(
    name: str,
    group_id: str | None = None,
    description: str | None = None,
    confirm: bool = False,
) -> str:
    """Create or update a device group. Device groups are used in policy source
    predicates to control access by device membership.

    Args:
        name: Human-readable group name.
        group_id: UUID to update an existing group; omit to create.
        description: Optional group description.
        confirm: Set to true to execute.
    """
    data: dict[str, Any] = {"name": name}
    if group_id:
        data["id"] = group_id
    if description:
        data["description"] = description

    action = "update device group" if group_id else "create device group"
    if _needs_confirmation(confirm):
        return _confirmation_required("upsert_device_group", action, data)
    try:
        return _ok(await _get_client().upsert_device_group(data))
    except Exception as e:
        return _error("upsert_device_group", e)


@app.tool()
async def add_devices_to_group(
    group_id: str, device_ids: list[str], confirm: bool = False
) -> str:
    """Add devices to a device group.

    Args:
        group_id: The group to add devices to.
        device_ids: List of device UUIDs to add.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "add_devices_to_group",
            "add devices to group",
            {"group_id": group_id, "device_ids": device_ids},
        )
    try:
        return _ok(
            await _get_client().add_devices_to_group(group_id, device_ids)
        )
    except Exception as e:
        return _error("add_devices_to_group", e)


@app.tool()
async def remove_devices_from_group(
    group_id: str, device_ids: list[str], confirm: bool = False
) -> str:
    """Remove devices from a device group.

    Args:
        group_id: The group to remove devices from.
        device_ids: List of device UUIDs to remove.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "remove_devices_from_group",
            "remove devices from group",
            {"group_id": group_id, "device_ids": device_ids},
        )
    try:
        return _ok(
            await _get_client().remove_devices_from_group(group_id, device_ids)
        )
    except Exception as e:
        return _error("remove_devices_from_group", e)


@app.tool()
async def delete_device_group(group_id: str, confirm: bool = False) -> str:
    """Delete a device group. Policies referencing this group will need to be updated.

    Args:
        group_id: UUID of the group to delete.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "delete_device_group", "delete device group", {"group_id": group_id}
        )
    try:
        return _ok(await _get_client().delete_device_group(group_id))
    except Exception as e:
        return _error("delete_device_group", e)


# -- Policy Writes -----------------------------------------------------


@app.tool()
async def upsert_resource(
    name: str,
    protocol: str,
    location_type: str,
    location_value: str,
    port_start: int | None = None,
    port_end: int | None = None,
    ports: list[int] | None = None,
    resource_id: str | None = None,
    confirm: bool = False,
) -> str:
    """Create or update a network resource. Resources define what can be accessed.

    Args:
        name: Human-readable resource name (e.g., "Production DB").
        protocol: One of: all, tcp, udp, http, https, icmp4, icmp6.
        location_type: One of: ip, cidr, dns, collection.
            - ip: a single IP (e.g. "192.0.2.1")
            - cidr: a CIDR range (e.g. "10.0.0.0/8")
            - dns: a domain name (e.g. "db.internal.example.com")
            - collection: a collection UUID
        location_value: The value matching the location type.
        port_start: Start of port range (inclusive). Use with port_end for a range.
        port_end: End of port range (inclusive). Use with port_start.
        ports: List of individual ports. Use instead of port_start/port_end.
        resource_id: UUID to update existing; omit to create new.
        confirm: Set to true to execute.
    """
    rid = resource_id or str(uuid.uuid4())
    location = {"type": location_type, "value": location_value}

    if port_start is not None and port_end is not None:
        ports_obj = {"range": [port_start, port_end]}
    elif ports:
        ports_obj = {"collection": {"ports": ports}}
    else:
        ports_obj = {"range": [0, 65535]}

    data = {
        "id": rid,
        "name": name,
        "protocol": protocol,
        "location": location,
        "ports": ports_obj,
    }

    action = "update resource" if resource_id else "create resource"
    if _needs_confirmation(confirm):
        return _confirmation_required("upsert_resource", action, data)
    try:
        return _ok(await _get_client().upsert_resource(data))
    except Exception as e:
        return _error("upsert_resource", e)


@app.tool()
async def upsert_resource_group(
    name: str,
    resource_ids: list[str],
    inherited_group_ids: list[str] | None = None,
    group_id: str | None = None,
    confirm: bool = False,
) -> str:
    """Create or update a resource group. Resource groups bundle resources together
    and are used as the 'destination' in policies.

    Args:
        name: Human-readable group name (e.g., "Engineering Resources").
        resource_ids: List of resource UUIDs to include directly.
        inherited_group_ids: Other resource group UUIDs whose resources to inherit.
        group_id: UUID to update existing; omit to create new.
        confirm: Set to true to execute.
    """
    data = {
        "id": group_id or str(uuid.uuid4()),
        "name": name,
        "resources": resource_ids,
        "inherited": inherited_group_ids or [],
    }
    action = "update resource group" if group_id else "create resource group"
    if _needs_confirmation(confirm):
        return _confirmation_required("upsert_resource_group", action, data)
    try:
        return _ok(await _get_client().upsert_resource_group(data))
    except Exception as e:
        return _error("upsert_resource_group", e)


@app.tool()
async def upsert_policy(
    source_predicate: str,
    dest_group_id: str,
    action: str,
    source_value: str | None = None,
    policy_id: str | None = None,
    order: int | None = None,
    status: str | None = None,
    confirm: bool = False,
) -> str:
    """Create or update a network access policy. Policies are the core of Bowtie's
    zero-trust model — they determine who can access what.

    Args:
        source_predicate: Who this policy matches. One of:
            - "Always" — all accepted devices (use sparingly)
            - "AuthenticatedUser" — any device with an authenticated user session
            - "InUserGroup" — devices whose user is in the specified group (provide group UUID in source_value)
            - "InDeviceGroup" — devices in the specified device group (provide group UUID in source_value)
            - "User" — a specific user (provide user UUID in source_value)
            - "Device" — a specific device (provide device UUID in source_value)
            For complex logic (Or/And/Nor), pass source_predicate as a JSON string of the full Source object.
        dest_group_id: UUID of the resource group this policy targets.
        action: One of Accept, Reject, Drop.
        source_value: UUID required for InUserGroup, InDeviceGroup, User, Device predicates.
        policy_id: UUID to update existing; omit to create new.
        order: Policy evaluation order (lower = evaluated first).
        status: Enabled or Disabled.
        confirm: Set to true to execute.
    """
    pid = policy_id or str(uuid.uuid4())
    source_id = str(uuid.uuid4())

    # Build source predicate
    simple_predicates = {"Always", "AuthenticatedUser"}
    value_predicates = {"InUserGroup", "InDeviceGroup", "User", "Device"}

    if source_predicate in simple_predicates:
        predicate: Any = source_predicate
    elif source_predicate in value_predicates:
        if not source_value:
            return _error(
                "upsert_policy",
                ValueError(f"source_value is required for predicate '{source_predicate}'"),
            )
        predicate = {source_predicate: source_value}
    else:
        # Assume it's a JSON-encoded complex predicate (Or/And/Nor)
        try:
            predicate = json.loads(source_predicate)
        except json.JSONDecodeError:
            return _error(
                "upsert_policy",
                ValueError(
                    f"Invalid source_predicate '{source_predicate}'. "
                    "Use one of: Always, AuthenticatedUser, InUserGroup, InDeviceGroup, "
                    "User, Device, or a JSON-encoded complex predicate."
                ),
            )

    data: dict[str, Any] = {
        "id": pid,
        "source": {"id": source_id, "predicate": predicate},
        "dest": dest_group_id,
        "action": action,
    }
    if order is not None:
        data["order"] = order
    if status:
        data["status"] = status

    act = "update policy" if policy_id else "create policy"
    if _needs_confirmation(confirm):
        return _confirmation_required("upsert_policy", act, data)
    try:
        return _ok(await _get_client().upsert_policy(data))
    except Exception as e:
        return _error("upsert_policy", e)


@app.tool()
async def force_policy_refresh(confirm: bool = False) -> str:
    """Force an immediate refresh of the policy engine on the controller.
    Normally the engine updates on an interval; use this for testing after changes.

    Args:
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "force_policy_refresh", "force policy engine refresh", {}
        )
    try:
        return _ok(await _get_client().force_policy_refresh())
    except Exception as e:
        return _error("force_policy_refresh", e)


# -- DNS Writes --------------------------------------------------------


@app.tool()
async def upsert_dns_config(
    name: str,
    server_addrs: list[str],
    strategy_resolver: str = "overlay",
    strategy_dns64: str = "never",
    is_search_domain: bool = False,
    is_log: bool = False,
    dns_id: str | None = None,
    include_only_site_ids: list[str] | None = None,
    confirm: bool = False,
) -> str:
    """Create or update a DNS configuration for an internal domain.

    Args:
        name: The domain name (e.g., "internal.example.com").
        server_addrs: List of upstream DNS server IPs (e.g., ["10.0.0.53", "10.0.0.54"]).
        strategy_resolver: How Bowtie resolves this domain:
            - "overlay" — resolve via both Bowtie and system DNS, prefer Bowtie
            - "exclusive" — only resolve via Bowtie's configured servers
            - "drop" — block all resolution for this domain
        strategy_dns64: DNS64 behavior: "preferred", "fallback", or "never".
        is_search_domain: If true, clients add this to their DNS search list.
            Must be true if using DNS64.
        is_log: Whether to log DNS queries for this domain.
        dns_id: UUID to update existing; omit to create new.
        include_only_site_ids: Limit this DNS config to specific sites (for overlapping IP space).
        confirm: Set to true to execute.
    """
    did = dns_id or str(uuid.uuid4())
    servers = {}
    for i, addr in enumerate(server_addrs):
        sid = str(uuid.uuid4())
        servers[sid] = {"id": sid, "addr": addr, "order": i}

    data: dict[str, Any] = {
        "id": did,
        "name": name,
        "servers": servers,
        "include_only_sites": include_only_site_ids or [],
        "is_counted": True,
        "is_log": is_log,
        "is_search_domain": is_search_domain,
        "dns64_exclude": {},
        "strategy_dns64": strategy_dns64,
        "strategy_resolver": strategy_resolver,
    }

    action = "update DNS config" if dns_id else "create DNS config"
    if _needs_confirmation(confirm):
        return _confirmation_required("upsert_dns_config", action, data)
    try:
        return _ok(await _get_client().upsert_dns_config(data))
    except Exception as e:
        return _error("upsert_dns_config", e)


@app.tool()
async def delete_dns_config(dns_id: str, confirm: bool = False) -> str:
    """Delete a DNS configuration.

    Args:
        dns_id: UUID of the DNS config to delete.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "delete_dns_config", "delete DNS config", {"dns_id": dns_id}
        )
    try:
        return _ok(await _get_client().delete_dns_config(dns_id))
    except Exception as e:
        return _error("delete_dns_config", e)


# -- Collection Writes -------------------------------------------------


@app.tool()
async def upsert_collection(
    name: str,
    description: str = "",
    collection_id: str | None = None,
    confirm: bool = False,
) -> str:
    """Create or update a collection. Collections group network locations
    (IPs, CIDRs, DNS names) for use in resources and route exclusions.

    Args:
        name: Human-readable collection name.
        description: Optional description.
        collection_id: UUID to update existing; omit to create new.
        confirm: Set to true to execute.
    """
    data: dict[str, Any] = {"name": name, "description": description}
    if collection_id:
        data["id"] = collection_id

    action = "update collection" if collection_id else "create collection"
    if _needs_confirmation(confirm):
        return _confirmation_required("upsert_collection", action, data)
    try:
        return _ok(await _get_client().upsert_collection(data))
    except Exception as e:
        return _error("upsert_collection", e)


@app.tool()
async def add_collection_members(
    collection_id: str,
    members: list[dict],
    confirm: bool = False,
) -> str:
    """Add members (network locations) to a collection.

    Each member needs: name, comment, location ({type, value}).
    Location types: ip, cidr, dns, collection.

    Example member: {"id": "auto-generated", "name": "Web Server", "comment": "",
                     "location": {"type": "ip", "value": "10.0.1.5"}}

    Args:
        collection_id: The collection to add members to.
        members: List of member objects. IDs will be auto-generated if missing.
        confirm: Set to true to execute.
    """
    for m in members:
        if "id" not in m:
            m["id"] = str(uuid.uuid4())
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "add_collection_members",
            f"add {len(members)} member(s) to collection",
            {"collection_id": collection_id, "members": members},
        )
    try:
        return _ok(
            await _get_client().add_collection_members(collection_id, members)
        )
    except Exception as e:
        return _error("add_collection_members", e)


@app.tool()
async def remove_collection_members(
    collection_id: str,
    member_ids: list[str],
    confirm: bool = False,
) -> str:
    """Remove members from a collection by their IDs.

    Args:
        collection_id: The collection to remove members from.
        member_ids: List of member UUIDs to remove.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "remove_collection_members",
            f"remove {len(member_ids)} member(s) from collection",
            {"collection_id": collection_id, "member_ids": member_ids},
        )
    try:
        return _ok(
            await _get_client().remove_collection_members(collection_id, member_ids)
        )
    except Exception as e:
        return _error("remove_collection_members", e)


@app.tool()
async def delete_collection(collection_id: str, confirm: bool = False) -> str:
    """Delete a collection. Resources referencing it will need to be updated.

    Args:
        collection_id: UUID of the collection to delete.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "delete_collection", "delete collection", {"collection_id": collection_id}
        )
    try:
        return _ok(await _get_client().delete_collection(collection_id))
    except Exception as e:
        return _error("delete_collection", e)


# -- DNS Block List Writes ---------------------------------------------


@app.tool()
async def upsert_dns_block_list(
    name: str,
    upstream: str | None = None,
    contents: str | None = None,
    block_list_id: str | None = None,
    override_to_allow: str | None = None,
    confirm: bool = False,
) -> str:
    """Create or update a DNS block list.

    Args:
        name: Block list name.
        upstream: URL to fetch the block list from (e.g., a community hosts file).
        contents: Inline block list content (domain list). Use instead of upstream.
        block_list_id: UUID to update existing; omit to create new.
        override_to_allow: Domains to allow even if on the list.
        confirm: Set to true to execute.
    """
    data: dict[str, Any] = {"name": name}
    if block_list_id:
        data["id"] = block_list_id
    if upstream:
        data["upstream"] = upstream
    if contents:
        data["contents"] = contents
    if override_to_allow is not None:
        data["override_to_allow"] = override_to_allow

    action = "update DNS block list" if block_list_id else "create DNS block list"
    if _needs_confirmation(confirm):
        return _confirmation_required("upsert_dns_block_list", action, data)
    try:
        return _ok(await _get_client().upsert_dns_block_list(data))
    except Exception as e:
        return _error("upsert_dns_block_list", e)


@app.tool()
async def delete_dns_block_list(
    block_list_id: str, confirm: bool = False
) -> str:
    """Delete a DNS block list.

    Args:
        block_list_id: UUID of the block list to delete.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "delete_dns_block_list",
            "delete DNS block list",
            {"block_list_id": block_list_id},
        )
    try:
        return _ok(await _get_client().delete_dns_block_list(block_list_id))
    except Exception as e:
        return _error("delete_dns_block_list", e)


# -- Threat Category Writes --------------------------------------------


@app.tool()
async def toggle_threat_category(
    source_path: str, enabled: bool, confirm: bool = False
) -> str:
    """Enable or disable a threat intelligence category by its source_path
    (e.g., "malware/callhome", "illegal/phishing").

    Args:
        source_path: The category identifier (from list_threat_categories).
        enabled: True to enable blocking, False to disable.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "toggle_threat_category",
            f"{'enable' if enabled else 'disable'} threat category '{source_path}'",
            {"source_path": source_path, "enabled": enabled},
        )
    try:
        return _ok(
            await _get_client().toggle_threat_category(source_path, enabled)
        )
    except Exception as e:
        return _error("toggle_threat_category", e)


@app.tool()
async def activate_threat_intel(confirm: bool = False) -> str:
    """Activate Bowtie Threat Intel. Creates category entities, enables the feed,
    and kicks off a background sync.

    Args:
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "activate_threat_intel", "activate threat intelligence", {}
        )
    try:
        return _ok(await _get_client().activate_threat_intel())
    except Exception as e:
        return _error("activate_threat_intel", e)


@app.tool()
async def deactivate_threat_intel(confirm: bool = False) -> str:
    """Deactivate Bowtie Threat Intel.

    Args:
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "deactivate_threat_intel", "deactivate threat intelligence", {}
        )
    try:
        return _ok(await _get_client().deactivate_threat_intel())
    except Exception as e:
        return _error("deactivate_threat_intel", e)


# -- Route Exclusion Writes --------------------------------------------


@app.tool()
async def upsert_route_exclusion(
    name: str,
    collection_id: str,
    exclusion_id: str | None = None,
    confirm: bool = False,
) -> str:
    """Create or update a route exclusion. Route exclusions define CIDRs
    (via a collection) that bypass the Bowtie tunnel.

    Args:
        name: Human-readable name for the exclusion.
        collection_id: Collection containing the CIDRs to exclude.
        exclusion_id: UUID to update existing; omit to create new.
        confirm: Set to true to execute.
    """
    data: dict[str, Any] = {"name": name, "collection-id": collection_id}
    if exclusion_id:
        data["id"] = exclusion_id

    action = "update route exclusion" if exclusion_id else "create route exclusion"
    if _needs_confirmation(confirm):
        return _confirmation_required("upsert_route_exclusion", action, data)
    try:
        return _ok(await _get_client().upsert_route_exclusion(data))
    except Exception as e:
        return _error("upsert_route_exclusion", e)


@app.tool()
async def delete_route_exclusion(
    exclusion_id: str, confirm: bool = False
) -> str:
    """Delete a route exclusion.

    Args:
        exclusion_id: UUID of the route exclusion to delete.
        confirm: Set to true to execute.
    """
    if _needs_confirmation(confirm):
        return _confirmation_required(
            "delete_route_exclusion",
            "delete route exclusion",
            {"exclusion_id": exclusion_id},
        )
    try:
        return _ok(await _get_client().delete_route_exclusion(exclusion_id))
    except Exception as e:
        return _error("delete_route_exclusion", e)


# ======================================================================
# MCP Prompts — guided multi-step workflows
# ======================================================================


@app.prompt()
def onboard_team(team_name: str, resource_descriptions: str, access_action: str = "Accept") -> str:
    """Guide the user through onboarding a team: create a user group, define resources,
    create a resource group, and set up a policy granting access."""
    return f"""You are helping an admin onboard the "{team_name}" team in Bowtie.

Follow these steps using the available tools:

1. **Create a user group** called "{team_name}" using upsert_user_group.
2. **Create resources** for each item described below using upsert_resource:
   {resource_descriptions}
3. **Create a resource group** called "{team_name} Resources" containing all the resources from step 2, using upsert_resource_group.
4. **Create a policy** using upsert_policy with:
   - source_predicate: "InUserGroup"
   - source_value: the user group ID from step 1
   - dest_group_id: the resource group ID from step 3
   - action: "{access_action}"
5. **Summarize** what was created and remind the admin to add users to the group.

For each write operation, call with confirm=false first to preview, then confirm=true to execute.
"""


@app.prompt()
def audit_policies() -> str:
    """Audit all policies, resources, and resource groups for security issues."""
    return """You are auditing the Bowtie network policy configuration.

1. Call get_policy to retrieve the full policy document.
2. Call list_user_groups and list_devices (or device groups if available) for context.
3. Analyze each policy for potential issues:
   - Policies using "Always" source predicate (matches all devices) — flag as overly permissive
   - Policies with "Accept" action on broad CIDRs (e.g., 0.0.0.0/0, 10.0.0.0/8) — flag for review
   - Policies without an order set — could cause evaluation surprises
   - Disabled policies that might be stale
4. For each finding, explain the risk and suggest a tighter alternative.
5. Present a summary table: Policy ID | Source | Destination | Action | Finding
"""


@app.prompt()
def troubleshoot_access(target: str, user_or_device_id: str | None = None) -> str:
    """Troubleshoot why a user/device can or cannot access a destination."""
    context = f' for user/device "{user_or_device_id}"' if user_or_device_id else ""
    return f"""You are troubleshooting network access to "{target}"{context}.

Follow these diagnostic steps:

1. **Identify the device/user**: If a user or device ID was given, call get_device or get_user.
   Check the device state (must be 'accepted') and that a user is assigned.
2. **Check policies**: Call get_policy. Find policies whose destination resources match
   the target "{target}" (check resource locations for IP/CIDR/DNS matches).
3. **Check source matching**: For each matching policy, check if the user/device would
   match the source predicate. Check group memberships if needed.
4. **Check DNS**: Call list_dns_configs to see if the target domain is configured.
   Check resolver strategy (overlay vs exclusive vs drop).
5. **Summarize**: Explain the access decision — which policy matched (or didn't),
   why access is granted or denied, and what to change to fix it.
"""


@app.prompt()
def review_pending_devices() -> str:
    """Review and batch approve or reject pending devices."""
    return """You are reviewing devices pending approval in Bowtie.

1. Call list_devices with state="pending" to get all pending devices.
2. For each pending device, show:
   - Device name, OS, type
   - Serial number (if available)
   - Assigned user (if any)
   - Last seen / reported public IP
3. Present the list as a table and ask the admin which devices to approve or reject.
4. Use change_device_state to batch-process the decisions.
   Call with confirm=false first to preview, then confirm=true to execute.
5. After processing, show a summary of what changed.
"""
