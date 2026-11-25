"""ONE_LINK_UI_PORT: test daemons must be able to stay off the product's UI ports.

Unset keeps the historical policy (7117, then the fallback range, then an
OS-assigned port). ``0`` skips the preferred range entirely. ``N`` binds exactly
N or fails startup loudly; it never falls back. Anything else is a startup
error naming the variable. Port-policy tests never touch 7117..7132 (a real
daemon may own them): the preferred range is pointed at free ephemeral ports.
"""

from __future__ import annotations

import socket
from contextlib import closing

import pytest
import pytest_asyncio
from aiohttp import web

import one_link.server as server_mod
from one_link.server import (
    UI_PORT_ENV,
    UIServer,
    UiPortStartupError,
    ui_port_override,
)

HOST = "127.0.0.1"


def _free_port_pair() -> int:
    """A port P such that P and P+1 were both free a moment ago."""

    for _ in range(64):
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as probe:
            probe.bind((HOST, 0))
            port = int(probe.getsockname()[1])
        if port >= 65535:
            continue
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as a, closing(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ) as b:
                a.bind((HOST, port))
                b.bind((HOST, port + 1))
        except OSError:
            continue
        return port
    raise RuntimeError("no adjacent free ports")


def _hold(port: int) -> socket.socket:
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.bind((HOST, port))
    holder.listen(1)
    return holder


@pytest_asyncio.fixture
async def srv():
    """A UIServer carrying only an AppRunner: the listener policy under test."""

    app_runner = web.AppRunner(web.Application())
    await app_runner.setup()
    server = UIServer.__new__(UIServer)
    server.runner = app_runner
    try:
        yield server
    finally:
        await app_runner.cleanup()


@pytest.fixture
def attempts(monkeypatch) -> list[int]:
    """Every candidate passes through the exclusive-bind seam first, on every
    platform (it returns None off Windows), so it records the attempt order."""

    seen: list[int] = []
    original = UIServer._bind_exclusive_socket

    def recording(host: str, port: int):
        seen.append(port)
        return original(host, port)

    monkeypatch.setattr(UIServer, "_bind_exclusive_socket", staticmethod(recording))
    return seen


@pytest.fixture
def preferred_range(monkeypatch) -> int:
    base = _free_port_pair()
    monkeypatch.setattr(server_mod, "PREFERRED_UI_PORT", base)
    monkeypatch.setattr(server_mod, "UI_PORT_FALLBACK_RANGE", 2)
    return base


# ─── parsing ───────────────────────────────────────────────────────────


def test_unset_variable_means_the_historical_policy() -> None:
    assert ui_port_override({}) is None


@pytest.mark.parametrize("raw,expected", [("0", 0), ("1", 1), ("8080", 8080), (" 65535 ", 65535)])
def test_valid_values_parse(raw: str, expected: int) -> None:
    assert ui_port_override({UI_PORT_ENV: raw}) == expected


@pytest.mark.parametrize("raw", ["", " ", "abc", "-1", "+5", "65536", "7117x", "1e3", "0x10", "٣"])
def test_invalid_values_are_startup_errors_naming_the_variable(raw: str) -> None:
    with pytest.raises(UiPortStartupError, match=UI_PORT_ENV) as excinfo:
        ui_port_override({UI_PORT_ENV: raw})
    assert excinfo.value.fatal_startup is True


@pytest.mark.asyncio
async def test_invalid_value_fails_start_before_any_state_is_touched(monkeypatch) -> None:
    monkeypatch.setenv(UI_PORT_ENV, "not-a-port")
    bare = UIServer.__new__(UIServer)
    with pytest.raises(UiPortStartupError, match=UI_PORT_ENV):
        await bare.start()
    assert not hasattr(bare, "_closing")
    assert not hasattr(bare, "runner")


# ─── binding ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_unset_binds_preferred_port_then_falls_back_as_before(
    srv, attempts, preferred_range
) -> None:
    base = preferred_range
    await srv._bind_ui_listener(HOST, None)
    assert srv.port == base and attempts == [base]
    await srv.site.stop()

    holder = _hold(base)
    try:
        attempts.clear()
        await srv._bind_ui_listener(HOST, None)
        assert srv.port == base + 1
        assert attempts == [base, base + 1]
        await srv.site.stop()
    finally:
        holder.close()


@pytest.mark.asyncio
async def test_zero_skips_the_preferred_range_and_binds_an_os_port(
    srv, attempts, preferred_range
) -> None:
    await srv._bind_ui_listener(HOST, 0)
    try:
        assert attempts == [0]
        assert 0 < srv.port <= 65535
        with closing(socket.create_connection((HOST, srv.port), timeout=2.0)):
            pass
    finally:
        await srv.site.stop()


@pytest.mark.asyncio
async def test_exact_port_binds_exactly_that_port(srv, attempts) -> None:
    wanted = _free_port_pair()
    await srv._bind_ui_listener(HOST, wanted)
    try:
        assert srv.port == wanted
        assert attempts == [wanted]
    finally:
        await srv.site.stop()


@pytest.mark.asyncio
async def test_exact_port_in_use_fails_loudly_without_fallback(
    srv, attempts, preferred_range
) -> None:
    taken = _free_port_pair()
    holder = _hold(taken)
    try:
        with pytest.raises(UiPortStartupError) as excinfo:
            await srv._bind_ui_listener(HOST, taken)
    finally:
        holder.close()
    message = str(excinfo.value)
    assert UI_PORT_ENV in message and str(taken) in message
    assert "refusing to fall back" in message
    assert attempts == [taken]
    assert not hasattr(srv, "site")

