"""Encrypted channel: handshake + AEAD stream over an in-memory pipe."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
import logging
import os
import threading
import time
from pathlib import Path

import pytest
import pytest_asyncio

from one_link import channel as ch
from one_link import daemon as daemon_mod
from one_link.daemon import Daemon
from one_link.identity import Identity, load_or_create


ConnectedPair = tuple[
    asyncio.StreamReader,
    asyncio.StreamWriter,
    asyncio.StreamReader,
    asyncio.StreamWriter,
]
ConnectedPairFactory = Callable[[], Awaitable[ConnectedPair]]
ChannelPairFactory = Callable[[Identity, Identity], Awaitable[tuple[ch.Channel, ch.Channel]]]


async def _close_stream_writers(writers: list[asyncio.StreamWriter]) -> None:
    """Close every test stream while pytest's owning event loop is alive."""
    for writer in writers:
        writer.close()

    async def _wait_closed(writer: asyncio.StreamWriter) -> None:
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError, RuntimeError):
            # A peer may already have reset a negative-path handshake socket.
            # The local transport has still been explicitly closed above.
            pass

    async with asyncio.timeout(5):
        await asyncio.gather(*(_wait_closed(writer) for writer in writers))


async def _finish_tasks(tasks: list[asyncio.Task[None]]) -> None:
    """Await owned callbacks, cancelling them if shutdown stops progressing."""
    if not tasks:
        return
    try:
        async with asyncio.timeout(5):
            await asyncio.gather(*tasks)
    finally:
        pending = [task for task in tasks if not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)


@pytest_asyncio.fixture
async def connected_pair() -> AsyncIterator[ConnectedPairFactory]:
    """Create loopback pairs and own every listener and accepted stream."""
    writers: list[asyncio.StreamWriter] = []
    servers: list[asyncio.AbstractServer] = []
    callback_tasks: list[asyncio.Task[None]] = []
    keepalive_events: list[asyncio.Event] = []

    async def _open() -> ConnectedPair:
        loop = asyncio.get_running_loop()
        accepted: asyncio.Future[tuple[asyncio.StreamReader, asyncio.StreamWriter]] = (
            loop.create_future()
        )
        keepalive = asyncio.Event()
        keepalive_events.append(keepalive)

        async def _server_cb(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            task = asyncio.current_task()
            if task is not None:
                callback_tasks.append(task)
            writers.append(writer)
            if not accepted.done():
                accepted.set_result((reader, writer))
            await keepalive.wait()

        server = await asyncio.start_server(_server_cb, "127.0.0.1", 0)
        servers.append(server)
        try:
            port = server.sockets[0].getsockname()[1]
            client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)
            writers.append(client_writer)
            server_reader, server_writer = await accepted
        except BaseException:
            server.close()
            await server.wait_closed()
            raise

        return (
            client_reader,
            client_writer,
            server_reader,
            server_writer,
        )

    try:
        yield _open
    finally:
        for server in servers:
            server.close()
        for keepalive in keepalive_events:
            keepalive.set()
        await _close_stream_writers(writers)
        await _finish_tasks(callback_tasks)
        await asyncio.gather(*(server.wait_closed() for server in servers))


@pytest_asyncio.fixture
async def channel_pair(
    connected_pair: ConnectedPairFactory,
) -> AsyncIterator[ChannelPairFactory]:
    """Open authenticated channels and close them even after a failed assertion."""
    channels: list[ch.Channel] = []

    async def _open(alice: Identity, bob: Identity) -> tuple[ch.Channel, ch.Channel]:
        alice_reader, alice_writer, bob_reader, bob_writer = await connected_pair()
        tasks = (
            asyncio.create_task(
                ch.initiate(
                    alice_reader,
                    alice_writer,
                    alice,
                    expected_responder_ed_pub=bob.public_bytes,
                )
            ),
            asyncio.create_task(ch.respond(bob_reader, bob_writer, bob)),
        )
        try:
            alice_channel, bob_channel = await asyncio.gather(*tasks)
        except BaseException:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        channels.extend((alice_channel, bob_channel))
        return alice_channel, bob_channel

    try:
        yield _open
    finally:
        async with asyncio.timeout(5):
            await asyncio.gather(*(channel.close() for channel in reversed(channels)))


def test_handshake_replay_check_insert_is_atomic_across_threads():
    """Exactly one concurrent observer may claim a fresh HELLO nonce.

    The barrier makes every worker contend on the same check-and-insert
    boundary.  This remains a meaningful regression test on free-threaded
    Python, where relying on the historical GIL would admit duplicate HELLOs.
    """

    workers = 32
    barrier = threading.Barrier(workers)
    peer_key = os.urandom(32)
    nonce = os.urandom(ch.NONCE_LEN)
    observed_at = time.monotonic()

    def _contend() -> bool:
        barrier.wait(timeout=10)
        return ch._handshake_replay_seen(peer_key, nonce, observed_at)

    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda _index: _contend(), range(workers)))
        assert results.count(False) == 1
        assert results.count(True) == workers - 1
    finally:
        with ch._handshake_replay_lock:
            ch._handshake_replay_cache.pop((peer_key, nonce), None)


@pytest.mark.asyncio
async def test_handshake_succeeds(tmp_path: Path, channel_pair: ChannelPairFactory):
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")
    a_chan, b_chan = await channel_pair(alice, bob)

    assert a_chan.peer_short_id == bob.short_id
    assert b_chan.peer_short_id == alice.short_id
    assert a_chan.peer_ed_pub == bob.public_bytes
    assert b_chan.peer_ed_pub == alice.public_bytes
    assert len(a_chan.transcript_hash) == 32
    assert a_chan.transcript_hash == b_chan.transcript_hash


@pytest.mark.asyncio
async def test_empty_pre_handshake_disconnect_is_benign(tmp_path: Path, caplog):
    """Reachability probes can open a TCP socket and close before sending
    the 4-byte frame header. That should not look like a protocol failure
    in production logs."""
    bob = load_or_create(tmp_path / "b.key")
    daemon = Daemon(bob)
    handler_tasks: list[asyncio.Task[None]] = []

    def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        handler_tasks.append(asyncio.create_task(daemon._handle_peer(reader, writer)))

    server = await asyncio.start_server(_handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    caplog.set_level(logging.WARNING, logger="one_link.daemon")
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.close()
        await writer.wait_closed()
        await asyncio.sleep(0.1)
    finally:
        server.close()
        await server.wait_closed()
        await _finish_tasks(handler_tasks)

    assert "handshake failed" not in caplog.text


def test_windows_proactor_reset_exception_handler_suppresses_teardown_noise(monkeypatch):
    calls = []

    class _Loop:
        def get_exception_handler(self):
            return None

        def set_exception_handler(self, handler):
            self.handler = handler

        def default_exception_handler(self, context):
            calls.append(context)

    exc = ConnectionResetError("reset")
    exc.winerror = 10054
    loop = _Loop()
    monkeypatch.setattr(daemon_mod.os, "name", "nt")

    daemon_mod._install_asyncio_exception_handler(loop)  # type: ignore[arg-type]
    loop.handler(loop, {"message": "connection_lost", "exception": exc})

    assert calls == []


def test_asyncio_exception_handler_delegates_real_errors(monkeypatch):
    calls = []

    class _Loop:
        def get_exception_handler(self):
            return None

        def set_exception_handler(self, handler):
            self.handler = handler

        def default_exception_handler(self, context):
            calls.append(context)

    loop = _Loop()
    monkeypatch.setattr(daemon_mod.os, "name", "nt")

    daemon_mod._install_asyncio_exception_handler(loop)  # type: ignore[arg-type]
    ctx = {"message": "boom", "exception": RuntimeError("real failure")}
    loop.handler(loop, ctx)

    assert calls == [ctx]


@pytest.mark.asyncio
async def test_send_recv_round_trip(tmp_path: Path, channel_pair: ChannelPairFactory):
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")
    a_chan, b_chan = await channel_pair(alice, bob)

    await a_chan.send(b"hello bob")
    assert await b_chan.recv() == b"hello bob"

    await b_chan.send(b"hi alice")
    assert await a_chan.recv() == b"hi alice"


@pytest.mark.asyncio
async def test_many_messages_keep_keys_aligned(tmp_path: Path, channel_pair: ChannelPairFactory):
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")
    a_chan, b_chan = await channel_pair(alice, bob)
    for i in range(50):
        await a_chan.send(f"msg-{i}".encode())
    for i in range(50):
        assert await b_chan.recv() == f"msg-{i}".encode()


@pytest.mark.asyncio
async def test_bidirectional_interleaved(tmp_path: Path, channel_pair: ChannelPairFactory):
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")
    a_chan, b_chan = await channel_pair(alice, bob)
    await a_chan.send(b"a1")
    await b_chan.send(b"b1")
    assert await b_chan.recv() == b"a1"
    assert await a_chan.recv() == b"b1"
    await a_chan.send(b"a2")
    await b_chan.send(b"b2")
    assert await a_chan.recv() == b"b2"
    assert await b_chan.recv() == b"a2"


@pytest.mark.asyncio
async def test_large_payload(tmp_path: Path, channel_pair: ChannelPairFactory):
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")
    a_chan, b_chan = await channel_pair(alice, bob)
    payload = os.urandom(1024 * 1024)  # 1 MiB
    # A new channel accepts only small frames until its owner says the peer
    # is trusted (tests/test_peer_admission.py covers the untrusted case).
    from one_link.wire import MAX_FRAME

    b_chan.max_inbound_frame = MAX_FRAME
    await a_chan.send(payload)
    assert await b_chan.recv() == payload


@pytest.mark.asyncio
async def test_responder_rejects_bad_initiator_signature(
    tmp_path: Path, connected_pair: ConnectedPairFactory
):
    """If initiator's HELLO signature doesn't verify, responder must abort."""
    bob = load_or_create(tmp_path / "b.key")
    _a_r, a_w, b_r, b_w = await connected_pair()

    # Send a bogus HELLO: random bytes that match expected length.
    from one_link.wire import write_frame

    bogus = os.urandom(32 + 32 + ch.NONCE_LEN + 64)
    await write_frame(a_w, bogus)

    with pytest.raises(RuntimeError, match="HELLO signature invalid"):
        await ch.respond(b_r, b_w, bob)


@pytest.mark.asyncio
async def test_initiator_rejects_bad_responder_signature(
    tmp_path: Path, connected_pair: ConnectedPairFactory
):
    """If responder's REPLY signature doesn't verify, initiator must abort."""
    alice = load_or_create(tmp_path / "a.key")
    a_r, a_w, b_r, b_w = await connected_pair()

    # Spawn the legitimate initiator
    init_task = asyncio.create_task(
        ch.initiate(
            a_r,
            a_w,
            alice,
            expected_responder_ed_pub=os.urandom(32),
        )
    )

    try:
        # Manually read the HELLO that initiator just sent
        from one_link.wire import read_frame, write_frame

        _ = await read_frame(b_r)

        # Send a bogus REPLY
        bogus = os.urandom(32 + 32 + ch.NONCE_LEN + 64)
        await write_frame(b_w, bogus)

        with pytest.raises(RuntimeError, match="REPLY signature invalid"):
            await init_task
    finally:
        if not init_task.done():
            init_task.cancel()
            await asyncio.gather(init_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_responder_rejects_short_hello(tmp_path: Path, connected_pair: ConnectedPairFactory):
    bob = load_or_create(tmp_path / "b.key")
    _a_r, a_w, b_r, b_w = await connected_pair()
    from one_link.wire import write_frame

    await write_frame(a_w, b"too short")
    with pytest.raises(RuntimeError, match="bad HELLO length"):
        await ch.respond(b_r, b_w, bob)


@pytest.mark.asyncio
async def test_aead_rejects_tampered_ciphertext(tmp_path: Path, channel_pair: ChannelPairFactory):
    """Flip a byte in a ciphertext frame; recv must raise."""
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")
    a_chan, b_chan = await channel_pair(alice, bob)

    # Send a legitimate frame, then immediately corrupt the wire by sending
    # a malformed encrypted frame *manually*.
    from one_link.wire import write_frame

    bad_ct = os.urandom(64)  # not a valid AEAD ciphertext under any key
    await write_frame(a_chan.writer, bad_ct)
    a_chan.tx_seq += 1  # keep sender state honest

    with pytest.raises(Exception):  # InvalidTag from cryptography
        await b_chan.recv()


@pytest.mark.asyncio
async def test_each_handshake_uses_fresh_ephemeral(
    tmp_path: Path, channel_pair: ChannelPairFactory
):
    """Two channels between same identities should derive different keys."""
    alice = load_or_create(tmp_path / "a.key")
    bob = load_or_create(tmp_path / "b.key")

    c1a, c1b = await channel_pair(alice, bob)
    c2a, c2b = await channel_pair(alice, bob)

    # Internal ChaCha20Poly1305 key bytes aren't exposed; instead, verify
    # that ciphertexts of the same plaintext differ across sessions.
    pt = b"the same plaintext"
    await c1a.send(pt)
    await c2a.send(pt)
    # We can't snoop the ciphertext through the abstraction, but we can at
    # least verify both channels work independently with no key reuse:
    assert await c1b.recv() == pt
    assert await c2b.recv() == pt
    assert c1a.transcript_hash != c2a.transcript_hash
