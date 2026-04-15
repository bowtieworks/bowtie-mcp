"""Tests for the bowtie-mcp CLI entrypoint."""

from __future__ import annotations


def test_main_runs_stdio(monkeypatch):
    from bowtie_mcp import __main__ as cli

    called: dict[str, str] = {}
    monkeypatch.setattr(cli.app, "run", lambda **kwargs: called.update(kwargs))

    cli.main([])

    assert called == {"transport": "stdio"}


def test_main_sets_port_for_sse(monkeypatch):
    from bowtie_mcp import __main__ as cli

    called: dict[str, str] = {}
    monkeypatch.setattr(cli.app, "run", lambda **kwargs: called.update(kwargs))
    monkeypatch.setattr(cli.app.settings, "port", cli.app.settings.port)

    cli.main(["--transport", "sse", "--port", "9001"])

    assert called == {"transport": "sse"}
    assert cli.app.settings.port == 9001


def test_main_supports_streamable_http(monkeypatch):
    from bowtie_mcp import __main__ as cli

    called: dict[str, str] = {}
    monkeypatch.setattr(cli.app, "run", lambda **kwargs: called.update(kwargs))
    monkeypatch.setattr(cli.app.settings, "port", cli.app.settings.port)

    cli.main(["--transport", "streamable-http", "--port", "9100"])

    assert called == {"transport": "streamable-http"}
    assert cli.app.settings.port == 9100
