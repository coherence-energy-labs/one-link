"""One source address cannot occupy every rendezvous connection slot."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from one_link.rendezvous_server import RendezvousApp, ServerConfig


def _request(ip: str) -> SimpleNamespace:
    transport = SimpleNamespace(get_extra_info=lambda _key: (ip, 40000))
    return SimpleNamespace(transport=transport, headers={})


class _Held:
    """Handlers that stay in flight until released."""

    def __init__(self, app: RendezvousApp) -> None:
        self.app = app
        self.release = asyncio.Event()
        self.tasks: list[asyncio.Task] = []

    async def _handler(self, _request):
        await self.release.wait()
        return "served"

    async def open(self, ip: str):
        task = asyncio.ensure_future(
            self.app._concurrency_middleware(_request(ip), self._handler)
        )
        self.tasks.append(task)
        await asyncio.sleep(0)
        return task

    async def close(self) -> list:
        self.release.set()
        return await asyncio.gather(*self.tasks)


def _app(**overrides) -> RendezvousApp:
    return RendezvousApp(ServerConfig(host="127.0.0.1", port=0, **overrides))


@pytest.mark.asyncio
async def test_one_address_is_held_to_its_share() -> None:
    app = _app(max_concurrent_connections=8, max_concurrent_per_source=3)
    held = _Held(app)
    for _ in range(3):
        await held.open("203.0.113.7")
    refused = await held.open("203.0.113.7")
    assert refused.done() and refused.result().status == 429

    # The server still has room, so a different address is served.
    other = await held.open("203.0.113.8")
    assert not other.done()

    results = await held.close()
    assert results.count("served") == 4
    assert app._concurrent == 0
    assert app._concurrent_by_source == {}


@pytest.mark.asyncio
async def test_global_cap_still_applies_across_addresses() -> None:
    app = _app(max_concurrent_connections=4, max_concurrent_per_source=2)
    held = _Held(app)
    for i in range(4):
        await held.open(f"198.51.100.{i}")
    full = await held.open("198.51.100.200")
    assert full.done() and full.result().status == 503
    await held.close()
    assert app._concurrent_by_source == {}


@pytest.mark.asyncio
async def test_ipv6_addresses_in_one_routed_prefix_share_a_limit() -> None:
    app = _app(max_concurrent_connections=8, max_concurrent_per_source=2)
    held = _Held(app)
    await held.open("2001:db8:1:2::1")
    await held.open("2001:db8:1:2:ffff::9")
    same_prefix = await held.open("2001:db8:1:2:abcd::1")
    assert same_prefix.done() and same_prefix.result().status == 429
    other_prefix = await held.open("2001:db8:1:3::1")
    assert not other_prefix.done()
    await held.close()


@pytest.mark.asyncio
async def test_slot_is_returned_when_the_handler_fails() -> None:
    app = _app(max_concurrent_connections=4, max_concurrent_per_source=1)

    async def boom(_request):
        raise RuntimeError("handler failed")

    with pytest.raises(RuntimeError):
        await app._concurrency_middleware(_request("192.0.2.1"), boom)
    assert app._concurrent == 0
    assert app._concurrent_by_source == {}


def test_per_source_share_cannot_exceed_the_global_cap() -> None:
    with pytest.raises(ValueError, match="max_concurrent_per_source"):
        _app(max_concurrent_connections=4, max_concurrent_per_source=5)
    with pytest.raises(ValueError, match="max_concurrent_per_source"):
        _app(max_concurrent_per_source=0)
