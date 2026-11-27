"""What a peer without standing can make this daemon do.

Every test here is an abuse case: the remote party completed a handshake with
a key it minted for free, was never pinned, and now tries to cost the daemon
time, memory, disk or the owner's attention.
"""

from __future__ import annotations

import ast
import asyncio
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from one_link import call_lifecycle, channel, peer_admission
from one_link import daemon as daemon_module
from one_link import wire
from one_link.daemon import Daemon
from one_link.identity import load_or_create
from one_link.pairing import MAX_PAIR_CONTEXTS, PairingTracker, PairState
from one_link.peer_admission import (
    MESSAGE_GATES,
    BoundedDict,
    Gate,
    PromptBudget,
    StrangerBudget,
)
from one_link.state import State
from one_link.wire import (
    HANDSHAKE_MAX_FRAME,
    MAX_FRAME,
    MAX_JSON_CONTAINERS,
    MAX_JSON_DEPTH,
    UNPINNED_MAX_FRAME,
    decode_msg,
    encode_msg,
    make_msg,
    read_frame,
)


# ─── frame ceilings ─────────────────────────────────────────────────


def _reader_with(data: bytes) -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    return reader


@pytest.mark.asyncio
async def test_oversize_frame_is_refused_from_its_length_prefix() -> None:
    # Only the 4-byte length is available. A read that waited for the payload
    # would hang here; the ceiling has to decide from the header alone.
    reader = _reader_with((UNPINNED_MAX_FRAME + 1).to_bytes(4, "big"))
    with pytest.raises(ValueError, match="frame too large"):
        await asyncio.wait_for(read_frame(reader, UNPINNED_MAX_FRAME), timeout=1)


@pytest.mark.asyncio
async def test_frame_ceiling_cannot_be_raised_above_the_protocol_cap() -> None:
    reader = _reader_with((MAX_FRAME + 1).to_bytes(4, "big"))
    with pytest.raises(ValueError, match="frame too large"):
        await asyncio.wait_for(read_frame(reader, MAX_FRAME * 4), timeout=1)


@pytest.mark.asyncio
async def test_callable_ceiling_is_read_after_the_header_arrives() -> None:
    reader = asyncio.StreamReader()
    ceiling = {"value": 8}
    pending = asyncio.ensure_future(read_frame(reader, lambda: ceiling["value"]))
    await asyncio.sleep(0)
    # Trust is granted while the read is already waiting. The frame that
    # arrives afterwards must be judged by the new ceiling.
    ceiling["value"] = 64
    reader.feed_data((32).to_bytes(4, "big") + b"x" * 32)
    assert await asyncio.wait_for(pending, timeout=1) == b"x" * 32


def test_ceilings_are_ordered() -> None:
    assert HANDSHAKE_MAX_FRAME < UNPINNED_MAX_FRAME < MAX_FRAME
    assert peer_admission.inbound_frame_ceiling(False) == UNPINNED_MAX_FRAME
    assert peer_admission.inbound_frame_ceiling(True) == MAX_FRAME


# ─── JSON depth check ───────────────────────────────────────────────


def _reference_depth_ok(data: bytes, max_depth: int) -> bool:
    """The original byte-at-a-time scan, kept as the oracle."""
    depth = 0
    in_string = False
    escaped = False
    for c in data:
        if in_string:
            if escaped:
                escaped = False
            elif c == 0x5C:
                escaped = True
            elif c == 0x22:
                in_string = False
            continue
        if c == 0x22:
            in_string = True
        elif c in (0x7B, 0x5B):
            depth += 1
            if depth > max_depth:
                return False
        elif c in (0x7D, 0x5D) and depth > 0:
            depth -= 1
    return True


def _depth_ok(data: bytes, max_depth: int) -> bool:
    try:
        wire._check_json_depth(data, max_depth)
    except ValueError:
        return False
    return True


@pytest.mark.parametrize("window", [1, 2, 3, 7, 1 << 20])
def test_depth_check_agrees_with_the_reference_scan(window: int, monkeypatch) -> None:
    import random

    monkeypatch.setattr(wire, "_STRIP_WINDOW", window)
    rng = random.Random(0x0DE7)
    structure = [b"{", b"}", b"[", b"]", b":", b",", b"1", b" "]
    # Backslashes only ever appear inside strings, as they do in anything a
    # JSON parser reads past. Escaped quotes and escaped backslashes are the
    # cases that decide whether a following bracket is structure or text.
    string_units = [b"a", b"{", b"[", b"}", b"]", b"\\\\", b'\\"', b"\\n", b" "]

    def token() -> bytes:
        if rng.random() < 0.35:
            body = b"".join(rng.choice(string_units) for _ in range(rng.randrange(0, 6)))
            return b'"' + body + b'"'
        return rng.choice(structure)

    for _ in range(1200):
        blob = b"".join(token() for _ in range(rng.randrange(0, 30)))
        if rng.random() < 0.1:
            blob += b'"' + rng.choice(string_units)  # unterminated string
        for max_depth in (1, 2, 5):
            assert _depth_ok(blob, max_depth) == _reference_depth_ok(blob, max_depth), blob


def test_brackets_inside_strings_do_not_count_as_nesting() -> None:
    payload = b'{"x":"' + b"[" * (MAX_JSON_DEPTH * 4) + b'"}'
    wire._check_json_depth(payload)
    escaped = b'{"x":"\\"' + b"{" * (MAX_JSON_DEPTH * 4) + b'\\\\"}'
    wire._check_json_depth(escaped)


def test_deep_nesting_is_refused() -> None:
    with pytest.raises(ValueError, match="nesting too deep"):
        wire._check_json_depth(b"[" * (MAX_JSON_DEPTH + 1) + b"]" * (MAX_JSON_DEPTH + 1))


def test_container_bomb_is_refused_before_parsing() -> None:
    # Flat, so depth is fine, but it would allocate over a million lists.
    bomb = b"[" + b"[]," * (MAX_JSON_CONTAINERS + 10) + b"[]]"
    with pytest.raises(ValueError, match="too complex"):
        wire._check_json_depth(bomb)


def test_largest_legal_frame_no_longer_stalls_the_event_loop() -> None:
    # One 16 MiB file chunk. The byte-at-a-time scan took over a second here,
    # all of it on the event loop. Half a second leaves a slow CI machine a
    # wide margin over the ~15 ms this takes now.
    body = b'{"t":"FILE_CHUNK","data":"' + b"A" * (MAX_FRAME - 64) + b'"}'
    started = time.perf_counter()
    wire._check_json_depth(body)
    assert time.perf_counter() - started < 0.5


# ─── handshake ──────────────────────────────────────────────────────


async def _connected_pair():
    accepted = asyncio.get_running_loop().create_future()
    hold = asyncio.Event()

    async def accept(reader, writer):
        accepted.set_result((reader, writer))
        await hold.wait()

    server = await asyncio.start_server(accept, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)
    server_reader, server_writer = await accepted
    return client_reader, client_writer, server_reader, server_writer, server, hold


async def _close_pair(pair) -> None:
    _cr, cw, _sr, sw, server, hold = pair
    cw.close()
    sw.close()
    hold.set()
    server.close()
    await server.wait_closed()
    await asyncio.gather(cw.wait_closed(), sw.wait_closed(), return_exceptions=True)


@pytest.mark.asyncio
async def test_responder_refuses_a_large_first_frame_unread(tmp_path: Path) -> None:
    bob = load_or_create(tmp_path / "bob.key")
    pair = await _connected_pair()
    _cr, cw, sr, sw, _server, _hold = pair
    try:
        # Announce a megabyte and send none of it.
        cw.write((1024 * 1024).to_bytes(4, "big"))
        await cw.drain()
        with pytest.raises(ValueError, match="frame too large"):
            await asyncio.wait_for(channel.respond(sr, sw, bob), timeout=5)
    finally:
        await _close_pair(pair)


async def _capture_hello(alice, bob) -> bytes:
    """Run a real initiator against a sink and keep the HELLO it sends."""
    pair = await _connected_pair()
    cr, cw, sr, _sw, _server, _hold = pair
    try:
        dial = asyncio.ensure_future(
            channel.initiate(cr, cw, alice, expected_responder_ed_pub=bob.public_bytes)
        )
        hello = await asyncio.wait_for(read_frame(sr, HANDSHAKE_MAX_FRAME), timeout=5)
        dial.cancel()
        await asyncio.gather(dial, return_exceptions=True)
        return hello
    finally:
        await _close_pair(pair)


async def _deliver_hello(bob, hello: bytes) -> BaseException | None:
    """Give ``hello`` to a fresh responder. Returns its failure, or ``None``
    if it accepted the HELLO and answered."""
    pair = await _connected_pair()
    _cr, cw, sr, sw, _server, _hold = pair
    try:
        cw.write(len(hello).to_bytes(4, "big") + hello)
        await cw.drain()
        responding = asyncio.ensure_future(channel.respond(sr, sw, bob))
        answered = asyncio.ensure_future(read_frame(_cr, HANDSHAKE_MAX_FRAME))
        done, _ = await asyncio.wait(
            {responding, answered}, timeout=5, return_when=asyncio.FIRST_COMPLETED
        )
        failure = None
        if responding in done:
            failure = responding.exception()
        for task in (responding, answered):
            task.cancel()
        await asyncio.gather(responding, answered, return_exceptions=True)
        return failure
    finally:
        await _close_pair(pair)


@pytest.mark.asyncio
async def test_forged_hello_cannot_burn_the_real_senders_nonce(tmp_path: Path) -> None:
    alice = load_or_create(tmp_path / "alice.key")
    bob = load_or_create(tmp_path / "bob.key")
    hello = await _capture_hello(alice, bob)

    # Same sender key and nonce, broken signature. Anyone on the path can
    # produce this without Alice's private key.
    forged = hello[:-1] + bytes([hello[-1] ^ 0x01])
    failure = await _deliver_hello(bob, forged)
    assert failure is not None
    assert "replay" not in str(failure).lower()

    # Alice's genuine HELLO must still be accepted afterwards.
    assert await _deliver_hello(bob, hello) is None

    # And only now, having been verified once, is it a replay.
    replayed = await _deliver_hello(bob, hello)
    assert replayed is not None and "replay" in str(replayed).lower()


def test_replay_lookup_never_inserts() -> None:
    key, nonce = b"k" * 32, b"n" * 32
    now = time.monotonic()
    with channel._handshake_replay_lock:
        channel._handshake_replay_cache.pop((key, nonce), None)
        before = len(channel._handshake_replay_cache)
    assert channel._handshake_replay_known(key, nonce, now) is False
    with channel._handshake_replay_lock:
        assert len(channel._handshake_replay_cache) == before
    assert channel._handshake_replay_seen(key, nonce, now) is False
    assert channel._handshake_replay_known(key, nonce, now) is True
    with channel._handshake_replay_lock:
        channel._handshake_replay_cache.pop((key, nonce), None)


# ─── channel ceiling follows standing ───────────────────────────────


async def _live_channels(alice, bob):
    pair = await _connected_pair()
    ar, aw, br, bw, _server, _hold = pair
    initiator, responder = await asyncio.gather(
        channel.initiate(ar, aw, alice, expected_responder_ed_pub=bob.public_bytes),
        channel.respond(br, bw, bob),
    )
    return initiator, responder, pair


@pytest.mark.asyncio
async def test_new_channel_starts_at_the_stranger_ceiling(tmp_path: Path) -> None:
    alice = load_or_create(tmp_path / "alice.key")
    bob = load_or_create(tmp_path / "bob.key")
    initiator, responder, pair = await _live_channels(alice, bob)
    try:
        assert responder.max_inbound_frame == UNPINNED_MAX_FRAME
        await initiator.send(b"x" * (UNPINNED_MAX_FRAME + 1024))
        with pytest.raises(ValueError, match="frame too large"):
            await asyncio.wait_for(responder.recv(), timeout=5)
    finally:
        await _close_pair(pair)


@pytest.mark.asyncio
async def test_policy_lifts_the_ceiling_for_the_next_frame(tmp_path: Path) -> None:
    alice = load_or_create(tmp_path / "alice.key")
    bob = load_or_create(tmp_path / "bob.key")
    initiator, responder, pair = await _live_channels(alice, bob)
    try:
        trusted = {"value": False}
        responder.inbound_frame_policy = lambda: peer_admission.inbound_frame_ceiling(
            trusted["value"]
        )
        waiting = asyncio.ensure_future(responder.recv())
        await asyncio.sleep(0)
        trusted["value"] = True
        big = b"y" * (UNPINNED_MAX_FRAME + 1024)
        await initiator.send(big)
        assert await asyncio.wait_for(waiting, timeout=5) == big
        assert responder.max_inbound_frame == MAX_FRAME
    finally:
        await _close_pair(pair)


def _daemon_with_state(tmp_path: Path, name: str = "me"):
    me = load_or_create(tmp_path / f"{name}.key")
    daemon = Daemon(me)
    daemon.state = State(db_path=tmp_path / f"{name}.db")
    return daemon, me


def _know(daemon: Daemon, peer, trust: str | None = None) -> None:
    daemon.state.upsert_peer(
        fingerprint=peer.fingerprint, short_id=peer.short_id, pubkey=peer.public_bytes
    )
    if trust is not None:
        daemon.state.set_peer_trust(peer.fingerprint, trust)


def test_standing_requires_a_pin_or_a_trusted_grant(tmp_path: Path) -> None:
    daemon, _me = _daemon_with_state(tmp_path)
    them = load_or_create(tmp_path / "them.key")
    try:
        assert daemon.admission.has_standing(them.fingerprint, them.public_bytes) is False
        _know(daemon, them)
        assert daemon.admission.has_standing(them.fingerprint) is False
        daemon.state.set_peer_trust(them.fingerprint, "pinned")
        assert daemon.admission.has_standing(them.fingerprint) is True
        daemon.state.set_peer_trust(them.fingerprint, "rejected")
        assert daemon.admission.has_standing(them.fingerprint) is False
    finally:
        daemon.state.close()


def test_standing_fails_closed_without_state(tmp_path: Path) -> None:
    daemon = Daemon(load_or_create(tmp_path / "me.key"))
    daemon.state = None
    assert daemon.admission.has_standing("ab" * 32) is False


def test_bound_channel_follows_trust_without_reconnecting(tmp_path: Path) -> None:
    daemon, _me = _daemon_with_state(tmp_path)
    them = load_or_create(tmp_path / "them.key")
    try:
        _know(daemon, them)
        chan = SimpleNamespace(
            peer_ed_pub=them.public_bytes,
            inbound_frame_policy=None,
            max_inbound_frame=0,
        )
        admit = daemon.admission.bind_channel(chan, them.fingerprint)
        assert chan.max_inbound_frame == UNPINNED_MAX_FRAME
        # Without standing every frame is charged, and the allowance runs out.
        charged = sum(admit(64) for _ in range(peer_admission.STRANGER_FRAME_BURST + 5))
        assert charged == peer_admission.STRANGER_FRAME_BURST
        daemon.state.set_peer_trust(them.fingerprint, "pinned")
        assert chan.inbound_frame_policy() == MAX_FRAME
        chan.max_inbound_frame = chan.inbound_frame_policy()
        assert admit(MAX_FRAME) is True
    finally:
        daemon.state.close()


# ─── budgets and bounded bookkeeping ────────────────────────────────


def test_bounded_dict_forgets_the_oldest_entry() -> None:
    seen: BoundedDict[str, int] = BoundedDict(3)
    for i, key in enumerate("abcd"):
        seen[key] = i
    assert list(seen) == ["b", "c", "d"]
    seen["b"] = 9
    seen["e"] = 4
    assert list(seen) == ["d", "b", "e"]
    seen.setdefault("f", 5)
    assert len(seen) == 3
    with pytest.raises(ValueError):
        BoundedDict(0)


def test_stranger_budget_allows_a_burst_then_a_trickle() -> None:
    now = {"t": 100.0}
    budget = StrangerBudget(clock=lambda: now["t"])
    admitted = sum(budget.admit(64) for _ in range(peer_admission.STRANGER_FRAME_BURST * 2))
    assert admitted == peer_admission.STRANGER_FRAME_BURST
    now["t"] += 10.0
    refilled = sum(budget.admit(64) for _ in range(1000))
    assert refilled == int(10.0 * peer_admission.STRANGER_FRAMES_PER_S)


def test_stranger_budget_also_counts_bytes() -> None:
    now = {"t": 0.0}
    budget = StrangerBudget(clock=lambda: now["t"])
    frames = 0
    while budget.admit(UNPINNED_MAX_FRAME):
        frames += 1
    assert frames == peer_admission.STRANGER_BYTE_BURST // UNPINNED_MAX_FRAME


def test_prompt_budget_is_shared_and_refills_slowly() -> None:
    now = {"t": 0.0}
    budget = PromptBudget(clock=lambda: now["t"])
    assert sum(budget.admit() for _ in range(100)) == peer_admission.PROMPT_BURST
    now["t"] += peer_admission.PROMPT_REFILL_S
    assert budget.admit() is True
    assert budget.admit() is False


def test_daemon_bookkeeping_keyed_by_remote_fingerprints_is_bounded(tmp_path: Path) -> None:
    daemon = Daemon(load_or_create(tmp_path / "me.key"))
    for name in ("_inbound_regime", "_peer_presence", "_capability_request_seen"):
        store = getattr(daemon, name)
        assert isinstance(store, BoundedDict), name
        assert store.maxlen == peer_admission.PEER_BOOKKEEPING_MAX
    daemon._admit_inbound_chat_rate("ab" * 32)
    assert isinstance(daemon._text_rate_per_peer, BoundedDict)


# ─── pending peer rows ──────────────────────────────────────────────


def _pending(state: State, n: int, start: int = 0) -> list[str]:
    fps = []
    for i in range(start, start + n):
        fp = f"{i:064x}"
        state.upsert_peer(fingerprint=fp, short_id=fp[:8], pubkey=bytes([i % 256]) * 32)
        state._conn.execute(
            "UPDATE peers SET last_seen_ms = ? WHERE fingerprint = ?", (1000 + i, fp)
        )
        fps.append(fp)
    return fps


def test_surplus_pending_peers_are_pruned_oldest_first(tmp_path: Path) -> None:
    state = State(db_path=tmp_path / "s.db")
    try:
        fps = _pending(state, 40)
        assert state.prune_pending_peers(keep=40) == 0
        assert state.prune_pending_peers(keep=25) == 15
        left = {p.fingerprint for p in state.list_peers()}
        assert left == set(fps[15:])
    finally:
        state.close()


def test_prune_spares_pinned_rejected_touched_connected_and_peers_with_history(
    tmp_path: Path,
) -> None:
    state = State(db_path=tmp_path / "s.db")
    try:
        fps = _pending(state, 12)
        pinned, rejected, aliased, connected, historied = fps[:5]
        state.set_peer_trust(pinned, "pinned")
        state.set_peer_trust(rejected, "rejected")
        state._conn.execute(
            "UPDATE peers SET local_alias = 'Dana' WHERE fingerprint = ?", (aliased,)
        )
        # A table added by some later feature. Nobody told the pruner about
        # it; it must still protect the peer it refers to.
        state._conn.execute("CREATE TABLE later_feature (peer_fp TEXT, note TEXT)")
        state._conn.execute(
            "INSERT INTO later_feature(peer_fp, note) VALUES(?, 'x')", (historied,)
        )
        removed = state.prune_pending_peers(keep=0, protect={connected})
        left = {p.fingerprint for p in state.list_peers()}
        assert left == {pinned, rejected, aliased, connected, historied}
        assert removed == 7
    finally:
        state.close()


def test_prune_drops_cache_rows_and_low_severity_alerts_with_the_peer(tmp_path: Path) -> None:
    state = State(db_path=tmp_path / "s.db")
    try:
        first, second = "aa" * 32, "bb" * 32
        state.upsert_peer(fingerprint=first, short_id="aaaaaaaa", pubkey=b"\x01" * 32,
                          hostname="laptop")
        state.upsert_peer(fingerprint=second, short_id="bbbbbbbb", pubkey=b"\x02" * 32,
                          hostname="laptop")
        count = lambda table: state._conn.execute(  # noqa: E731
            f"SELECT COUNT(*) FROM {table}"
        ).fetchone()[0]
        assert count("hostname_keys") == 2
        assert count("key_change_events") == 1
        assert state.prune_pending_peers(keep=0) == 2
        assert count("peers") == 0
        assert count("hostname_keys") == 0
        assert count("key_change_events") == 0
    finally:
        state.close()


def test_prune_keeps_alerts_that_involve_a_pinned_peer(tmp_path: Path) -> None:
    state = State(db_path=tmp_path / "s.db")
    try:
        real, imposter = "aa" * 32, "bb" * 32
        state.upsert_peer(fingerprint=real, short_id="aaaaaaaa", pubkey=b"\x01" * 32,
                          hostname="laptop")
        state.set_peer_trust(real, "pinned")
        state.upsert_peer(fingerprint=imposter, short_id="bbbbbbbb", pubkey=b"\x02" * 32,
                          hostname="laptop")
        assert state.prune_pending_peers(keep=0) == 1
        rows = state._conn.execute(
            "SELECT severity, new_fingerprint FROM key_change_events"
        ).fetchall()
        assert [(r[0], r[1]) for r in rows] == [("high", imposter)]
    finally:
        state.close()


# ─── the real inbound path ──────────────────────────────────────────


async def _dial(server_daemon: Daemon, server_identity, tmp_path: Path, name: str):
    """Open a real channel to ``server_daemon`` as a fresh identity."""
    client, identity = _daemon_with_state(tmp_path, name)
    server = await asyncio.start_server(server_daemon._handle_peer, "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    chan = await channel.initiate(
        reader, writer, identity, expected_responder_ed_pub=server_identity.public_bytes
    )
    await asyncio.wait_for(client._negotiate_outbound_caps(chan, peer_label=name), timeout=10)
    return client, identity, chan, server, writer


async def _hang_up(client: Daemon, server, writer) -> None:
    writer.close()
    server.close()
    await asyncio.gather(writer.wait_closed(), server.wait_closed(), return_exceptions=True)
    client.state.close()


@pytest.mark.asyncio
async def test_stranger_is_disconnected_when_its_allowance_is_spent(tmp_path: Path) -> None:
    daemon, me = _daemon_with_state(tmp_path)
    client, them, chan, server, writer = await _dial(daemon, me, tmp_path, "stranger")
    try:
        flood = peer_admission.STRANGER_FRAME_BURST + 60
        for _ in range(flood):
            await chan.send(encode_msg(make_msg("PING", them.short_id)))
        pongs = 0
        with pytest.raises(asyncio.IncompleteReadError):
            while True:
                reply = decode_msg(await asyncio.wait_for(chan.recv(), timeout=10))
                pongs += reply.get("t") == "PONG"
        # CAPS used one frame of the burst; the rest were answered, then the
        # daemon hung up instead of working through the remainder.
        assert pongs == peer_admission.STRANGER_FRAME_BURST - 1
        assert daemon._inbound_peer_count == 0
        assert daemon._inbound_live_channels == {}
    finally:
        await _hang_up(client, server, writer)
        daemon.state.close()


@pytest.mark.asyncio
async def test_pinned_peer_is_not_subject_to_the_stranger_allowance(tmp_path: Path) -> None:
    daemon, me = _daemon_with_state(tmp_path)
    friend = load_or_create(tmp_path / "friend.key")
    _know(daemon, friend, "pinned")
    client, them, chan, server, writer = await _dial(daemon, me, tmp_path, "friend")
    try:
        assert them.fingerprint == friend.fingerprint
        flood = peer_admission.STRANGER_FRAME_BURST + 60
        for _ in range(flood):
            await chan.send(encode_msg(make_msg("PING", them.short_id)))
        pongs = 0
        while pongs < flood:
            reply = decode_msg(await asyncio.wait_for(chan.recv(), timeout=10))
            pongs += reply.get("t") == "PONG"
        assert pongs == flood
    finally:
        await _hang_up(client, server, writer)
        daemon.state.close()


@pytest.mark.asyncio
async def test_stranger_cannot_send_a_frame_above_its_ceiling(tmp_path: Path) -> None:
    daemon, me = _daemon_with_state(tmp_path)
    client, them, chan, server, writer = await _dial(daemon, me, tmp_path, "stranger")
    try:
        body = make_msg("TEXT", them.short_id, body="A" * (UNPINNED_MAX_FRAME + 4096))
        await chan.send(encode_msg(body))
        # The daemon hangs up with most of the frame unread, so the client
        # sees either a clean EOF or a reset.
        with pytest.raises((asyncio.IncompleteReadError, ConnectionError)):
            await asyncio.wait_for(chan.recv(), timeout=10)
        for _ in range(200):
            if daemon._inbound_peer_count == 0:
                break
            await asyncio.sleep(0.01)
        assert daemon._inbound_peer_count == 0
    finally:
        await _hang_up(client, server, writer)
        daemon.state.close()


class _FakeChannel:
    def __init__(self, peer) -> None:
        self.peer_ed_pub = peer.public_bytes
        self.peer_short_id = peer.short_id
        self.transcript_hash = b"\x07" * 32
        self.sent: list[dict] = []

    async def send(self, data: bytes) -> None:
        self.sent.append(decode_msg(data))


@pytest.mark.asyncio
async def test_pair_reject_from_a_stranger_changes_nothing(tmp_path: Path) -> None:
    daemon, _me = _daemon_with_state(tmp_path)
    stranger = load_or_create(tmp_path / "stranger.key")
    chan = _FakeChannel(stranger)
    try:
        await daemon._on_peer_message(chan, make_msg("PAIR_REJECT", stranger.short_id))
        assert chan.sent[-1].get("rejected") == "no_live_pair_context"
        assert daemon.state.get_peer(stranger.fingerprint) is None
    finally:
        daemon.state.close()


@pytest.mark.asyncio
async def test_pair_reject_still_ends_a_pairing_in_progress(tmp_path: Path) -> None:
    daemon, _me = _daemon_with_state(tmp_path)
    peer = load_or_create(tmp_path / "peer.key")
    chan = _FakeChannel(peer)
    try:
        await daemon._on_peer_message(chan, make_msg("PAIR_REQUEST", peer.short_id))
        assert daemon.pairing.get(peer.fingerprint).state is PairState.INCOMING
        await daemon._on_peer_message(chan, make_msg("PAIR_REJECT", peer.short_id))
        assert "rejected" not in chan.sent[-1]
        assert daemon.state.get_peer(peer.fingerprint).trust == "rejected"
    finally:
        daemon.state.close()


@pytest.mark.asyncio
async def test_pair_requests_from_many_strangers_share_one_allowance(tmp_path: Path) -> None:
    daemon, _me = _daemon_with_state(tmp_path)
    prompts: list[dict] = []
    daemon.ui_server = SimpleNamespace(broadcast=prompts.append)
    # A frozen clock: the allowance must not refill while the test creates
    # its identities, however long that takes on a slow machine.
    daemon.admission._prompts = PromptBudget(clock=lambda: 0.0)
    try:
        refused = 0
        for i in range(peer_admission.PROMPT_BURST + 20):
            stranger = load_or_create(tmp_path / f"s{i}.key")
            chan = _FakeChannel(stranger)
            await daemon._on_peer_message(chan, make_msg("PAIR_REQUEST", stranger.short_id))
            refused += chan.sent[-1].get("rejected") == "pair_request_rate_limited"
        shown = [p for p in prompts if p.get("type") == "pair_request"]
        assert len(shown) == peer_admission.PROMPT_BURST
        assert refused == 20
    finally:
        daemon.state.close()


@pytest.mark.asyncio
async def test_pinned_peer_can_always_ask_to_pair_again(tmp_path: Path) -> None:
    daemon, _me = _daemon_with_state(tmp_path)
    daemon.admission._prompts = PromptBudget(clock=lambda: 0.0)
    while daemon.admission._prompts.admit():
        pass
    friend = load_or_create(tmp_path / "friend.key")
    _know(daemon, friend, "pinned")
    chan = _FakeChannel(friend)
    try:
        await daemon._on_peer_message(chan, make_msg("PAIR_REQUEST", friend.short_id))
        assert "rejected" not in chan.sent[-1]
    finally:
        daemon.state.close()


def test_inbound_flood_cannot_evict_a_pairing_the_owner_started() -> None:
    manager = PairingTracker()
    manager.begin(peer_fp="mine", sas="111111", incoming=False)
    manager.we_confirm("mine")
    for i in range(MAX_PAIR_CONTEXTS * 2):
        manager.begin(peer_fp=f"flood-{i}", sas="000000", incoming=True)
    assert manager.get("mine") is not None
    assert manager.get("mine").state is PairState.CONFIRMED
    assert len(manager.all()) == MAX_PAIR_CONTEXTS


# ─── the dispatcher honours the declared gates ──────────────────────

_TRUST_CHECKS = {"_capability_allowed", "_is_pinned", "has_standing"}


def _dispatcher():
    tree = ast.parse(Path(daemon_module.__file__).read_text(encoding="utf-8"))
    constants: dict[str, set[str]] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if not isinstance(target, ast.Name):
                continue
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                constants[target.id] = {value.value}
            elif (
                isinstance(value, ast.Call)
                and getattr(value.func, "id", "") == "frozenset"
                and value.args
                and isinstance(value.args[0], (ast.Set, ast.List, ast.Tuple))
            ):
                constants[target.id] = {
                    e.value for e in value.args[0].elts if isinstance(e, ast.Constant)
                }
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Daemon")
    methods = {
        n.name: n for n in cls.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    return methods, constants


def _types_tested(test: ast.expr, constants: dict[str, set[str]]) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(test):
        if not (
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Name)
            and node.left.id == "t"
            and isinstance(node.ops[0], (ast.Eq, ast.In))
        ):
            continue
        for comparator in node.comparators:
            if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                found.add(comparator.value)
            elif isinstance(comparator, (ast.Set, ast.List, ast.Tuple)):
                found |= {e.value for e in comparator.elts if isinstance(e, ast.Constant)}
            elif isinstance(comparator, ast.Name):
                found |= constants.get(comparator.id, set())
    return found


def _calls(body: list[ast.stmt], methods) -> tuple[set[str], set[str]]:
    """Trust checks and other ``self`` methods called directly in ``body``."""
    checks: set[str] = set()
    callees: set[str] = set()
    for stmt in body:
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                name = node.func.attr
                if name in _TRUST_CHECKS:
                    checks.add(name)
                elif (
                    isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "self"
                    and name in methods
                ):
                    callees.add(name)
    return checks, callees


def _reaches_trust_check(body: list[ast.stmt], methods, depth: int = 3) -> bool:
    checks, frontier = _calls(body, methods)
    seen = {"_on_peer_message"}
    for _ in range(depth):
        if checks:
            return True
        following = set()
        for name in frontier - seen:
            seen.add(name)
            found, callees = _calls(methods[name].body, methods)
            checks |= found
            following |= callees
        frontier = following
    return bool(checks)


def _branches(methods, constants):
    """Yield ``(types, body)`` for each arm of the dispatcher's if/elif chains."""

    def walk(stmts: list[ast.stmt]):
        for stmt in stmts:
            node = stmt
            while isinstance(node, ast.If):
                types = _types_tested(node.test, constants)
                if types:
                    yield types, node.body
                if len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If):
                    node = node.orelse[0]
                else:
                    yield from walk(node.orelse)
                    break

    yield from walk(methods["_on_peer_message"].body)


def test_every_dispatched_message_type_has_a_declared_gate() -> None:
    methods, constants = _dispatcher()
    dispatched: set[str] = set()
    for types, _body in _branches(methods, constants):
        dispatched |= types
    assert dispatched - set(MESSAGE_GATES) == set(), (
        "message types handled by the dispatcher but missing from "
        "peer_admission.MESSAGE_GATES"
    )
    assert set(MESSAGE_GATES) - dispatched == set(), (
        "peer_admission.MESSAGE_GATES lists types the dispatcher no longer handles"
    )


def test_every_standing_gated_type_reaches_a_trust_check() -> None:
    methods, constants = _dispatcher()
    unchecked: set[str] = set()
    for types, body in _branches(methods, constants):
        gated = {t for t in types if MESSAGE_GATES.get(t) is Gate.STANDING}
        if gated and not _reaches_trust_check(body, methods):
            unchecked |= gated
    assert unchecked == set(), (
        "these handlers do work for a peer without checking pinned trust or a "
        "capability grant"
    )


def test_redispatch_types_only_feed_the_dispatcher() -> None:
    methods, constants = _dispatcher()
    for types, body in _branches(methods, constants):
        if any(MESSAGE_GATES.get(t) is Gate.REDISPATCH for t in types):
            _checks, callees = _calls(body, methods)
            assert callees == {"_on_peer_message"}, types


def test_call_plane_admission_lives_in_the_call_lifecycle_service() -> None:
    source = Path(call_lifecycle.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    dispatch = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, ast.AsyncFunctionDef) and n.name == "dispatch_wire_message"
    )
    called = {
        n.func.attr
        for n in ast.walk(dispatch)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert {"_admit_inbound_invite", "call_capability_allowed"} <= called
    call_plane = {t for t, gate in MESSAGE_GATES.items() if gate is Gate.CALL_PLANE}
    assert call_plane == set(daemon_module._LIVING_PRESENCE_WIRE_TYPES)


# ─── a queued send never guesses its recipient ──────────────────────


def test_pinned_name_resolution_is_exact_and_refuses_ambiguity(tmp_path: Path) -> None:
    daemon, _me = _daemon_with_state(tmp_path)
    daemon.discovery = None
    alice = load_or_create(tmp_path / "alice.key")
    malory = load_or_create(tmp_path / "malory.key")
    try:
        for peer, alias in ((alice, "Al"), (malory, "Malory")):
            _know(daemon, peer, "pinned")
            daemon.state._conn.execute(
                "UPDATE peers SET local_alias = ? WHERE fingerprint = ?",
                (alias, peer.fingerprint),
            )
        resolve = daemon._resolve_pinned_peer_fp
        # "al" is Alice's alias exactly. It is also a substring of "Malory",
        # which used to make the answer depend on who was seen last.
        assert resolve("al") == alice.fingerprint
        assert resolve("malory") == malory.fingerprint
        # Part of a name is accepted when only one peer has it...
        assert resolve("alo") == malory.fingerprint
        # ...and refused when two do ("a" is in both "Al" and "Malory").
        assert resolve("a") is None
        assert resolve("nobody") is None
        assert resolve(alice.fingerprint) == alice.fingerprint
        assert resolve(alice.fingerprint[:12]) == alice.fingerprint
        assert resolve(alice.fingerprint[:4]) is None
        # The same alias on two pinned peers names neither.
        daemon.state._conn.execute(
            "UPDATE peers SET local_alias = 'Al' WHERE fingerprint = ?",
            (malory.fingerprint,),
        )
        assert resolve("al") is None
    finally:
        daemon.state.close()


def test_each_daemon_gets_its_own_admission_controller(tmp_path: Path) -> None:
    first = Daemon(load_or_create(tmp_path / "a.key"))
    second = Daemon(load_or_create(tmp_path / "b.key"))
    assert first.admission is first.admission
    assert first.admission is not second.admission
    # A daemon built without __init__, as many tests do, still gets one.
    bare = Daemon.__new__(Daemon)
    assert isinstance(bare.admission, peer_admission.PeerAdmission)
    assert isinstance(Daemon.admission, peer_admission.PerDaemon)


# ─── key-change alerts stay proportionate ───────────────────────────


def _alerts(state: State) -> list[tuple[str, str, str]]:
    rows = state._conn.execute(
        "SELECT severity, old_fingerprint, new_fingerprint FROM key_change_events ORDER BY id"
    ).fetchall()
    return [(r[0], r[1], r[2]) for r in rows]


def test_a_hostname_cycling_through_keys_cannot_log_quadratic_alerts(tmp_path: Path) -> None:
    state = State(db_path=tmp_path / "s.db")
    try:
        count = 30
        for i in range(count):
            fp = f"{i + 1:064x}"
            state.upsert_peer(
                fingerprint=fp, short_id=fp[-8:], pubkey=bytes([i + 1]) * 32, hostname="kiosk"
            )
        cap = State._MAX_UNPINNED_KEY_CHANGE_ALERTS
        # The i-th key compares against at most `cap` earlier unpinned keys,
        # where it used to compare against all i of them (435 rows for 30).
        expected = sum(min(i, cap) for i in range(count))
        assert len(_alerts(state)) == expected
    finally:
        state.close()


def test_a_change_away_from_a_pinned_key_is_always_recorded(tmp_path: Path) -> None:
    state = State(db_path=tmp_path / "s.db")
    try:
        friend = "aa" * 32
        state.upsert_peer(fingerprint=friend, short_id="aaaaaaaa", pubkey=b"\xaa" * 32,
                          hostname="laptop")
        state.set_peer_trust(friend, "pinned")
        # Bury the pinned key under more throwaway keys than the cap.
        for i in range(State._MAX_UNPINNED_KEY_CHANGE_ALERTS + 6):
            fp = f"{i + 1:064x}"
            state.upsert_peer(
                fingerprint=fp, short_id=fp[-8:], pubkey=bytes([i + 1]) * 32, hostname="laptop"
            )
        imposter = "ee" * 32
        state.upsert_peer(fingerprint=imposter, short_id="eeeeeeee", pubkey=b"\xee" * 32,
                          hostname="laptop")
        assert ("high", friend, imposter) in _alerts(state)
    finally:
        state.close()
