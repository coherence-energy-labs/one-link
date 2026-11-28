"""A daemon that owes the caller a rotation certificate still answers the caller.

Why this file exists. When two daemons finish exchanging CAPS, each sends the
other any rotation certificate it still owes (``_drain_pending_rotation_certs_to``),
from inside its CAPS handler. On a ratcheted channel the side that accepted the
connection cannot send until it has read the caller's first ratcheted frame.
For the accepting side the CAPS handler runs in the very task that reads the
connection, so a send made there waited on a read that task could no longer
make. The handler never answered the caller, and it never ended either, even
after the caller hung up, because only the handler itself closes its channel:
each such connection kept one of that peer's inbound slots for the life of
the daemon.

It needs a daemon that has rotated its identity and a peer that calls it
before the certificate is acknowledged. A peer that can only call in (one
behind NAT, say) is never told of the rotation any other way.

Found by reading, while looking for the cause of an unrelated live failure in
the same feature, and confirmed here before anything was changed: the second
test below hung in its own teardown.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link import channel as channel_module
from one_link.capabilities import LOCAL_CAPABILITIES
from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.state import State
from one_link.wire import decode_msg, encode_msg, make_msg


def _identity(hostname: str) -> Identity:
    private = Ed25519PrivateKey.generate()
    public = private.public_key()
    public_bytes = public.public_bytes_raw()
    fingerprint = fingerprint_of(public_bytes)
    return Identity(
        private=private, public=public, public_bytes=public_bytes,
        fingerprint=fingerprint, short_id=fingerprint[:8], hostname=hostname,
    )


async def _call(tmp_path: Path, *, owed: int, caller_speaks: bool = True) -> dict[str, Any]:
    """Call a daemon that owes the caller ``owed`` certificates, exchange CAPS and (unless silent) PING it.

    Reports what the caller saw and what the daemon kept.
    """
    receiver, caller = _identity("receiver"), _identity("caller")
    daemon = Daemon(receiver)
    state = State(db_path=tmp_path / "state.db")
    daemon.state = state
    # One row per rotation the caller has not acknowledged: a daemon that
    # rotated twice before this peer called owes two. The store keeps one row
    # per (peer, new fingerprint), so each needs its own.
    for step in range(owed):
        state.queue_rotation_announcement(
            peer_fp=caller.fingerprint, old_fp=f"{step:064x}",
            new_fp=receiver.fingerprint if step == owed - 1 else f"{step + 1:064x}",
            cert_json="{}", sig_hex="00",
        )
    assert len(state.list_pending_rotation_announcements(peer_fp=caller.fingerprint, unacked_only=True)) == owed
    server = await asyncio.start_server(daemon._handle_peer, host="127.0.0.1", port=0)
    port = int(server.sockets[0].getsockname()[1])
    client = None
    frames: list[str] = []
    answered = False
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        client = await channel_module.initiate(
            reader, writer, caller, expected_responder_ed_pub=receiver.public_bytes,
        )
        server_caps = decode_msg(await asyncio.wait_for(client.recv(), timeout=2.0))
        assert server_caps["t"] == "CAPS"
        client.note_caps_received(list(server_caps.get("features") or []))
        await client.send(encode_msg(make_msg(
            "CAPS", caller.short_id, protocol="OL1.2", features=list(LOCAL_CAPABILITIES),
            channel_bind={
                "self_fp": caller.fingerprint, "peer_fp": receiver.fingerprint,
                "transcript": client.transcript_hex, "features": list(LOCAL_CAPABILITIES),
            },
        )))
        client.note_caps_sent()
        client.maybe_activate_ratchet()
        # The side that called can always send; only the side that accepted waits.
        assert client.is_ratchet_active and client.waits_for_peer_before_sending() is False
        if caller_speaks:
            ping = make_msg("PING", caller.short_id)
            await client.send(encode_msg(ping))
            try:
                while not answered:
                    frame = decode_msg(await asyncio.wait_for(client.recv(), timeout=3.0))
                    frames.append(str(frame["t"]))
                    answered = frame["t"] == "PONG" and frame["of"] == ping["id"]
            except asyncio.TimeoutError:
                pass
        else:
            # Long enough for the daemon to have read CAPS and reached its drain.
            await asyncio.sleep(0.5)
    finally:
        if client is not None:
            await client.close()
        server.close()
        # Since Python 3.12 this waits for every handler. One that never
        # returns would hold it for ever, so the wait is bounded and reported.
        try:
            await asyncio.wait_for(server.wait_closed(), timeout=3.0)
            handler_ended = True
        except asyncio.TimeoutError:
            handler_ended = False
        background = list(getattr(daemon, "_background_tasks", ()))
        if background:
            await asyncio.wait(background, timeout=2.0)
        result = {
            "frames": frames,
            "answered": answered,
            "handler_ended": handler_ended,
            "slots_still_held": daemon._inbound_per_fp.get(caller.fingerprint, 0),
            "connections_still_counted": daemon._inbound_peer_count,
            "tasks_still_running": sum(1 for task in background if not task.done()),
        }
        state.close()
    return result


_CLEAN = {"handler_ended": True, "slots_still_held": 0, "connections_still_counted": 0, "tasks_still_running": 0}


@pytest.mark.asyncio
async def test_a_daemon_that_owes_nothing_answers_the_ping(tmp_path: Path) -> None:
    assert await _call(tmp_path, owed=0) == {"frames": ["PONG"], "answered": True, **_CLEAN}


@pytest.mark.asyncio
@pytest.mark.parametrize("owed", [1, 2, 3])
async def test_a_daemon_sends_every_certificate_it_owes_before_it_answers(tmp_path: Path, owed: int) -> None:
    """All of them, not only the first. A reviewer of the first version of this
    change showed that with two owed, the second went out after the answer:
    the delivery took the send lock once per certificate and the answer got in
    between. The read loop now finishes the delivery before it answers."""
    assert await _call(tmp_path, owed=owed) == {
        "frames": ["ROTATION_CERT"] * owed + ["PONG"], "answered": True, **_CLEAN,
    }


@pytest.mark.asyncio
async def test_a_caller_that_hangs_up_before_the_certificate_can_be_sent_leaves_nothing_behind(tmp_path: Path) -> None:
    """The delivery waits for the caller's first ratcheted frame. If none comes, it ends with the connection."""
    assert await _call(tmp_path, owed=2, caller_speaks=False) == {
        "frames": [], "answered": False, **_CLEAN,
    }

@pytest.mark.asyncio
async def test_revoked_peer_before_caps_releases_connection_without_waiting(tmp_path: Path) -> None:
    """A refusal must not send from the task still responsible for reading CAPS."""
    receiver, caller = _identity("receiver"), _identity("caller")
    daemon = Daemon(receiver)
    state = State(db_path=tmp_path / "state.db")
    daemon.state = state
    handlers: set[asyncio.Task] = set()

    async def handle(reader, writer):
        task = asyncio.current_task()
        assert task is not None
        handlers.add(task)
        try:
            await daemon._handle_peer(reader, writer)
        finally:
            handlers.discard(task)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    client = None
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", server.sockets[0].getsockname()[1])
        client = await channel_module.initiate(
            reader, writer, caller, expected_responder_ed_pub=receiver.public_bytes,
        )
        server_caps = decode_msg(await asyncio.wait_for(client.recv(), timeout=2))
        assert server_caps["t"] == "CAPS"
        # The server has already admitted the connection. Revoke it in the
        # interval between that admission and receipt of the client's CAPS.
        state.set_peer_trust(caller.fingerprint, "rejected")
        client.note_caps_received(list(server_caps["features"]))
        await client.send(encode_msg(make_msg(
            "CAPS", caller.short_id, protocol="OL1.2", features=list(LOCAL_CAPABILITIES),
            channel_bind={"self_fp": caller.fingerprint, "peer_fp": receiver.fingerprint,
                          "transcript": client.transcript_hex, "features": list(LOCAL_CAPABILITIES)},
        )))
        client.note_caps_sent()
        client.maybe_activate_ratchet()
        with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
            await asyncio.wait_for(client.recv(), timeout=2)
        # The read task must exit, not just close the TCP writer.
        for _ in range(100):
            if not handlers:
                break
            await asyncio.sleep(0.01)
        assert not handlers
        assert daemon._inbound_peer_count == 0
        assert daemon._inbound_per_fp.get(caller.fingerprint, 0) == 0
    finally:
        if client is not None:
            await client.close()
        for task in list(handlers):
            task.cancel()
        await asyncio.gather(*list(handlers), return_exceptions=True)
        server.close()
        await asyncio.wait_for(server.wait_closed(), timeout=3)
        state.close()
