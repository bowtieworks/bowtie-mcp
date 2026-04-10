# Contributing to bowtie-mcp

Thanks for your interest in contributing! This MCP server lets admins manage their Bowtie cluster through any MCP-capable LLM client.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/bowtieworks/bowtie-mcp.git
cd bowtie-mcp

# Create a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install in development mode with test dependencies
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest
```

Tests use `pytest-httpx` to mock HTTP calls — no running Bowtie controller needed.

## Testing Against a Real Controller

```bash
export BOWTIE_HOST="https://your-controller"
export BOWTIE_USERNAME="admin@example.com"
export BOWTIE_PASSWORD="your-password"
python -m bowtie_mcp
```

## Project Structure

```
src/bowtie_mcp/
├── __init__.py       # Package metadata
├── __main__.py       # CLI entry point (stdio + SSE transport)
├── client.py         # Async HTTP client wrapping the Bowtie REST API
└── server.py         # MCP server with tool definitions and prompts
```

- **`client.py`** is a thin HTTP wrapper. No business logic — just auth and request/response handling.
- **`server.py`** owns tool definitions, the confirmation pattern, input construction, and error formatting.

## Adding a New Tool

1. Add the HTTP method to `client.py`
2. Add the tool handler to `server.py` with the `@app.tool()` decorator
3. For write tools, use the `_needs_confirmation()` / `_confirmation_required()` pattern
4. Add tests in `tests/test_client.py` and `tests/test_server.py`

## Code Style

- Format with `ruff format`
- Lint with `ruff check`
- Type check with `mypy` (not enforced in CI yet, but appreciated)

## Submitting Changes

1. Fork the repo and create a feature branch
2. Make your changes with tests
3. Run `pytest` to verify
4. Open a pull request with a clear description of what changed and why
