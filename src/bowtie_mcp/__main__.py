"""CLI entry point for the Bowtie MCP server."""

import argparse
import sys

from bowtie_mcp.server import app


def main() -> None:
    parser = argparse.ArgumentParser(description="Bowtie MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse"],
        default="stdio",
        help="MCP transport to use (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="Port for SSE transport (default: 8080)",
    )
    args = parser.parse_args()

    if args.transport == "sse":
        app.run(transport="sse", port=args.port)
    else:
        app.run(transport="stdio")


if __name__ == "__main__":
    main()
