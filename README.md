# Bowtie MCP Server

[![CI](https://github.com/bowtieworks/bowtie-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/bowtieworks/bowtie-mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/bowtie-mcp)](https://pypi.org/project/bowtie-mcp/)
[![Python](https://img.shields.io/pypi/pyversions/bowtie-mcp)](https://pypi.org/project/bowtie-mcp/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An [MCP](https://modelcontextprotocol.io) server for the [Bowtie](https://bowtie.works) control plane. Manage your Bowtie cluster — policies, devices, DNS, users, and more — using natural language through your LLM of choice or any MCP-capable client.

## Install

```bash
pip install bowtie-mcp
```

Or run without installing using [uvx](https://docs.astral.sh/uv/):

```bash
uvx bowtie-mcp
```

## Quick Start

### Claude Code

```bash
claude mcp add bowtie \
  -e BOWTIE_HOST="https://bt0.example.com" \
  -e BOWTIE_USERNAME="admin@example.com" \
  -e BOWTIE_PASSWORD="your-password" \
  -- uvx bowtie-mcp
```

### Claude Desktop

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "bowtie": {
      "command": "uvx",
      "args": ["bowtie-mcp"],
      "env": {
        "BOWTIE_HOST": "https://bt0.example.com",
        "BOWTIE_USERNAME": "admin@example.com",
        "BOWTIE_PASSWORD": "your-password"
      }
    }
  }
}
```

### Cursor / Windsurf

Add to `.cursor/mcp.json` or your editor's MCP config:

```json
{
  "mcpServers": {
    "bowtie": {
      "command": "uvx",
      "args": ["bowtie-mcp"],
      "env": {
        "BOWTIE_HOST": "https://bt0.example.com",
        "BOWTIE_USERNAME": "admin@example.com",
        "BOWTIE_PASSWORD": "your-password"
      }
    }
  }
}
```

## Authentication

The server authenticates to your Bowtie controller using admin credentials — the same approach used by the [Bowtie Terraform provider](https://registry.terraform.io/providers/bowtieworks/bowtie/latest).

| Variable | Required | Description |
|---|---|---|
| `BOWTIE_HOST` | Yes | Controller HTTPS endpoint (e.g., `https://bt0.example.com`) |
| `BOWTIE_USERNAME` | Yes | Admin email address |
| `BOWTIE_PASSWORD` | Yes | Admin password |
| `BOWTIE_MCP_SKIP_CONFIRMATION` | No | Set to `true` to skip write confirmation prompts |

Credentials are used by the local MCP server process to authenticate with your controller. They are never sent to or visible by the LLM.

## What You Can Do

Ask your LLM things like:

- *"List all pending devices and approve the ones from the engineering team"*
- *"Create a policy that gives the sales team access to the CRM on 10.0.5.0/24 port 443"*
- *"Why can't device X reach the production database?"*
- *"Audit our policies for anything overly permissive"*
- *"Set up DNS for internal.example.com pointing at 10.0.0.53"*

### Available Tools

**Read** (30+ tools) — List and inspect users, devices, device groups, user groups, policies, resources, resource groups, DNS configs, sites, collections, block lists, threat categories, controllers, route exclusions, and API keys.

**Write** (25+ tools) — Create, update, and delete all of the above. All write operations require explicit confirmation before executing (see below).

**Guided Workflows** (4 prompts):
| Prompt | Description |
|---|---|
| `onboard-team` | Create a user group, resources, resource group, and access policy |
| `audit-policies` | Review all policies for overly permissive rules |
| `troubleshoot-access` | Diagnose why a user/device can or can't reach a destination |
| `review-pending-devices` | Batch approve or reject pending devices |

### Write Confirmation

All write tools use a two-step confirmation pattern. The first call returns a preview of the planned change. Call again with `confirm=true` to execute. This prevents accidental mutations.

Set `BOWTIE_MCP_SKIP_CONFIRMATION=true` to bypass this for automation or CI workflows.

## Development

```bash
git clone https://github.com/bowtieworks/bowtie-mcp.git
cd bowtie-mcp
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## License

[MIT](LICENSE)
