"""Reachability prune for ghost peers."""

from __future__ import annotations

import asyncio

import aiohttp
import pytest

from one_link.discovery import Peer
from tests.harness import daemon_pair


pytestmark = pytest.mark.timeout(60)


@pytest.mark.asyncio
async def test_prune_removes_unreachable_peer(monkeypatch):
    """Synthetic test: stick a fake peer into the registry pointing at a port
    nothing is listening on. prune_unreachable should remove it."""
    from one_link.discovery import Discovery
    d = Discovery(short_id="aaaa", hostname="me", port=1, ed_pub_hex="00" * 32)
    # Don't start the real Zeroconf — we only need the registry.
    # Inject a "ghost" peer pointing at a port nothing is listening on.
    d.registry.upsert(Peer(
        short_id="ghost123",
        hostname="GhostPeer",
        address="127.0.0.1",
        port=1,  # essentially guaranteed no listener
        ed_pub_hex="ff" * 32,
    ))
    assert len(d.registry.peers) == 1
    removed = await d.prune_unreachable(timeout=0.3)
    assert removed == 1
    assert len(d.registry.peers) == 0


@pytest.mark.asyncio
async def test_prune_removes_malformed_peer_without_network_probe():
    from one_link.discovery import Discovery

    d = Discovery(short_id="aaaa", hostname="me", port=1, ed_pub_hex="00" * 32)
    d.registry.peers["ghost123"] = Peer(
        short_id="ghost123",
        hostname="GhostPeer",
        address="127.0.0.1",
        port=9,
        ed_pub_hex="",
    )

    removed = await d.prune_unreachable(timeout=0.01)

    assert removed == 1
    assert d.registry.peers == {}


@pytest.mark.asyncio
async def test_prune_removes_same_host_alien_peer_without_network_probe():
    from one_link.discovery import Discovery

    d = Discovery(short_id="aaaa", hostname="me", port=1, ed_pub_hex="00" * 32)
    d.registry.local_addresses = {"192.168.1.142"}
    d.registry.peers["ghost123"] = Peer(
        short_id="ghost123",
        hostname="GhostPeer",
        address="192.168.1.142",
        port=49999,
        ed_pub_hex="ff" * 32,
    )

    removed = await d.prune_unreachable(timeout=0.01)

    assert removed == 1
    assert d.registry.peers == {}


@pytest.mark.asyncio
async def test_prune_keeps_reachable_peer():
    """A peer pointing at a real listening port stays in the registry."""
    from one_link.discovery import Discovery
    # Start a tiny listener that accepts and immediately closes
    async def _server_cb(r, w):
        try:
            w.close()
        except Exception:
            pass
    server = await asyncio.start_server(_server_cb, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    try:
        d = Discovery(short_id="aaaa", hostname="me", port=1, ed_pub_hex="00" * 32)
        d.registry.upsert(Peer(
            short_id="real-peer",
            hostname="LivePeer",
            address="127.0.0.1",
            port=port,
            ed_pub_hex="ff" * 32,
        ))
        removed = await d.prune_unreachable(timeout=0.5)
        assert removed == 0
        assert len(d.registry.peers) == 1
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.live_daemon
@pytest.mark.asyncio
async def test_api_prune_endpoint():
    """The /api/peers/prune endpoint actually prunes the daemon's registry."""
    with daemon_pair() as p:
        port_a = int((p.a.home / "data" / "server.port").read_text().strip())
        token_a = (p.a.home / "data" / "ui.token").read_text().strip()
        base_a = f"http://127.0.0.1:{port_a}"

        # Inject a synthetic ghost into A's registry
        # We don't have direct access to the running daemon's Discovery;
        # the live daemon is a subprocess. So instead we just verify the
        # endpoint runs without error and reports counts.
        async with aiohttp.ClientSession() as s:
            async with s.post(
                f"{base_a}/api/peers/prune",
                headers={"Authorization": f"Bearer {token_a}"},
            ) as r:
                assert r.status == 200
                j = await r.json()
                assert "removed" in j
                assert "before" in j
                assert "after" in j
                # B should still be there (it's reachable)
                assert j["after"] >= 1
