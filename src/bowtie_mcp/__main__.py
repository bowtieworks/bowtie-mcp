"""CLI entry point for the Bowtie MCP server."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from bowtie_mcp.server import app


def main(argv: Sequence[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Bowtie MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport to use (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for HTTP transports (default: 8080)",
    )
    args = parser.parse_args(argv)

    if args.transport == "stdio":
        app.run(transport="stdio")
        return

    app.settings.port = args.port
    app.run(transport=args.transport)


if __name__ == "__main__":
    main()
