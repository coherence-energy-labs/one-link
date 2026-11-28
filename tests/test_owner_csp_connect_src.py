"""The owner page may connect to its own daemon and nowhere else."""

from __future__ import annotations

import pytest

from one_link.server import _owner_connect_src


@pytest.mark.parametrize(
    "host",
    ["127.0.0.1:7117", "localhost:7117", "laptop.local", "[::1]:7117", "192.168.1.20:443"],
)
def test_same_host_websocket_is_allowed_and_nothing_wider(host: str) -> None:
    directive = _owner_connect_src(host)
    assert directive == f"connect-src 'self' ws://{host} wss://{host}; "
    # No scheme-wide sources: those let an injected script reach any server.
    for wide in (" ws: ", " wss: ", " https: ", " http: ", " * "):
        assert wide not in directive.replace(";", " ")


@pytest.mark.parametrize(
    "host",
    [
        None,
        "",
        "evil.example; script-src *",
        "a b",
        "host\r\nX-Injected: 1",
        "host:port",
        "https://evil.example",
        "*",
        "-leading.example",
    ],
)
def test_a_host_header_that_is_not_a_plain_host_is_not_copied(host) -> None:
    assert _owner_connect_src(host) == "connect-src 'self'; "
