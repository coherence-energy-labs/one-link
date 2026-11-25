"""Raw-protocol tests: hand-craft messages directly to the daemon to verify
that defense-in-depth works against malicious peers.

These tests bypass the friendly `send_file` / `send` API and go straight to
the channel + wire layer to send things a well-behaved peer would never send.
"""

from __future__ import annotations

import asyncio
import base64
import socket
import time
from pathlib import Path

import blake3
import pytest

from one_link import channel as ch
from one_link.identity import fingerprint_of, load_or_create
from one_link.state import State
from one_link.wire import decode_msg, encode_msg, make_msg
from tests.harness import daemon_pair, inbox_files


pytestmark = pytest.mark.timeout(120)


def _daemon_public_key(home: Path) -> bytes:
    return load_or_create(home / "config" / "identity.key").public_bytes


def _authorize_raw_test_peer(home: Path, key_path: Path) -> None:
    """Pin the hand-crafted sender so protocol validation is reachable.

    Production now rejects every capability from pending identities. These
    tests need an authorized-but-malicious peer: otherwise a closed connection
    proves only the trust gate and never exercises filename, sequence, size, or
    blob validation.
    """
    identity = load_or_create(key_path)
    state = State(db_path=home / "data" / "state.db")
    try:
        state.upsert_peer(
            fingerprint=identity.fingerprint,
            short_id=identity.short_id,
            pubkey=identity.public_bytes,
            hostname="raw-protocol-test-peer",
            trust_default="pinned",
        )
        state.set_peer_trust(identity.fingerprint, "pinned", actor="test")
    finally:
        state.close()


async def _open_to(
    host: str,
    port: int,
    key_path: Path,
    expected_responder_ed_pub: bytes,
):
    me = load_or_create(key_path)
    reader, writer = await asyncio.open_connection(host, port)
    channel = await ch.initiate(
        reader,
        writer,
        me,
        expected_responder_ed_pub=expected_responder_ed_pub,
    )
    # A current daemon requires transcript-bound CAPS before accepting any
    # application frame. Advertise no optional features so this adversarial
    # client remains on the legacy channel cipher and the server does not
    # independently activate Double Ratchet.
    caps = make_msg(
        "CAPS",
        me.short_id,
        protocol="OL1.2",
        features=[],
        channel_bind={
            "self_fp": me.fingerprint,
            "peer_fp": fingerprint_of(expected_responder_ed_pub),
            "transcript": channel.transcript_hex,
            "features": [],
        },
    )
    await channel.send(encode_msg(caps))
    channel.note_caps_sent()
    server_caps = decode_msg(await channel.recv())
    if server_caps.get("t") != "CAPS":
        await channel.close()
        raise RuntimeError(f"raw test peer expected CAPS, got {server_caps!r}")
    # Complete the channel's authenticated CAPS state machine.  This raw
    # adversarial peer deliberately advertised no optional features, so the
    # negotiated intersection is empty even though the production daemon's
    # reply advertises features it supports.  Recording that empty
    # intersection releases the post-CAPS send barrier without activating a
    # one-sided Double Ratchet cutover.
    channel.note_caps_received([])
    if channel.maybe_activate_ratchet():
        await channel.close()
        raise RuntimeError("raw legacy test peer unexpectedly activated ratchet")
    return me, channel


# Bounded so a protocol-state regression names THIS boundary rather than
# consuming the two-minute process timeout above -- that intent is why the wait
# exists and it is kept.
#
# Raised from 10s after test_malicious_filename_stays_in_inbox[.] timed out
# here on windows-latest inside a 19-minute live-daemon job, having passed on
# the four preceding master commits. Nothing in that change touched the
# protocol. 10s for a live handshake plus transfer on the slowest runner under
# load measures the machine, not the wire format -- the same shape as the 5s
# budget on /api/power-status and the 2s hypothesis deadline fixed earlier.
#
# 45s is still comfortably inside the 120s process timeout, so a genuine hang
# is still reported at this line with its precise cause. If it fails HERE
# again at 45s, that is no longer plausibly load and should be read as a real
# protocol stall.
_RECV_BOUND_SECONDS = 45.0


async def _recv_non_caps(channel):
    while True:
        msg = decode_msg(
            await asyncio.wait_for(channel.recv(), timeout=_RECV_BOUND_SECONDS)
        )
        if msg.get("t") != "CAPS":
            return msg


async def _send_file_with_arbitrary_name(
    host: str,
    port: int,
    key_path: Path,
    expected_responder_ed_pub: bytes,
    wire_name: str,
    content: bytes,
) -> str:
    me, channel = await _open_to(
        host,
        port,
        key_path,
        expected_responder_ed_pub,
    )
    try:
        blob_hex = blake3.blake3(content).hexdigest()
        offer = make_msg(
            "FILE_OFFER",
            me.short_id,
            name=wire_name,
            size=len(content),
            blob=blob_hex,
        )
        await channel.send(encode_msg(offer))
        await _recv_non_caps(channel)  # offer ACK

        chunk = make_msg(
            "FILE_CHUNK",
            me.short_id,
            blob=blob_hex,
            seq=0,
            data=base64.b64encode(content).decode("ascii"),
            eof=True,
        )
        await channel.send(encode_msg(chunk))
        await _recv_non_caps(channel)  # chunk ACK
        return blob_hex
    finally:
        await channel.close()


# ───────────────────── Path traversal attacks ──────────────────────


@pytest.mark.live_daemon
@pytest.mark.parametrize(
    "evil_name",
    [
        "../../etc/passwd",
        "..\\..\\Windows\\System32\\evil.dll",
        "/etc/passwd",
        "C:\\Windows\\System32\\evil.dll",
        "subdir/inner.txt",
        "..",
        ".",
    ],
)
def test_malicious_filename_stays_in_inbox(evil_name: str):
    with daemon_pair(pin_trust=True) as p:
        # We need an identity key file to act as the "fake initiator". Use a
        # private temp key separate from either daemon's.
        attacker_key = p.tmp / "attacker.key"
        _authorize_raw_test_peer(p.b.home, attacker_key)
        content = b"this should never escape inbox/"
        # Find the responder peer port from the daemon's mDNS advertisement
        # — we know it's b.peer_port from the harness.
        asyncio.run(
            _send_file_with_arbitrary_name(
                "127.0.0.1",
                p.b.peer_port,
                attacker_key,
                _daemon_public_key(p.b.home),
                evil_name,
                content,
            )
        )
        time.sleep(0.5)
        inbox = p.b.home / "data" / "inbox"
        for f in inbox.iterdir():
            # Every file ends up directly inside inbox/, never in a parent.
            assert f.parent == inbox, f"path traversal escaped: {f}"
            # Filename must not contain path separators after the daemon's
            # `Path(...).name` strip.
            assert "/" not in f.name
            assert "\\" not in f.name
        # And nothing got written outside inbox by climbing up:
        bad_locations = [
            p.b.home / "etc",
            p.b.home / "Windows",
            p.b.home.parent / "etc",
            p.b.home / "passwd",
        ]
        for bad in bad_locations:
            assert not bad.exists(), f"attack succeeded: {bad}"


@pytest.mark.live_daemon
def test_invalid_file_offer_blob_is_rejected_without_file():
    with daemon_pair(pin_trust=True) as p:
        attacker_key = p.tmp / "attacker.key"
        _authorize_raw_test_peer(p.b.home, attacker_key)

        async def _attack():
            me, channel = await _open_to(
                "127.0.0.1",
                p.b.peer_port,
                attacker_key,
                _daemon_public_key(p.b.home),
            )
            try:
                offer = make_msg(
                    "FILE_OFFER",
                    me.short_id,
                    name="bad.bin",
                    size=4,
                    blob="not-a-blob",
                )
                await channel.send(encode_msg(offer))
            finally:
                await channel.close()

        asyncio.run(_attack())
        time.sleep(0.5)
        assert inbox_files(p.b.home) == []


@pytest.mark.live_daemon
def test_file_chunk_sequence_mismatch_deletes_partial_file():
    with daemon_pair(pin_trust=True) as p:
        attacker_key = p.tmp / "attacker.key"
        _authorize_raw_test_peer(p.b.home, attacker_key)

        async def _attack():
            me, channel = await _open_to(
                "127.0.0.1",
                p.b.peer_port,
                attacker_key,
                _daemon_public_key(p.b.home),
            )
            try:
                content = b"abcd"
                blob_hex = blake3.blake3(content).hexdigest()
                offer = make_msg(
                    "FILE_OFFER",
                    me.short_id,
                    name="seq.bin",
                    size=len(content),
                    blob=blob_hex,
                )
                await channel.send(encode_msg(offer))
                await _recv_non_caps(channel)
                chunk = make_msg(
                    "FILE_CHUNK",
                    me.short_id,
                    blob=blob_hex,
                    seq=1,
                    data=base64.b64encode(content).decode("ascii"),
                    eof=True,
                )
                await channel.send(encode_msg(chunk))
            finally:
                await channel.close()

        asyncio.run(_attack())
        time.sleep(0.5)
        assert inbox_files(p.b.home) == []


@pytest.mark.live_daemon
def test_file_chunk_declared_size_overrun_deletes_partial_file():
    with daemon_pair(pin_trust=True) as p:
        attacker_key = p.tmp / "attacker.key"
        _authorize_raw_test_peer(p.b.home, attacker_key)

        async def _attack():
            me, channel = await _open_to(
                "127.0.0.1",
                p.b.peer_port,
                attacker_key,
                _daemon_public_key(p.b.home),
            )
            try:
                content = b"too long"
                blob_hex = blake3.blake3(content).hexdigest()
                offer = make_msg(
                    "FILE_OFFER",
                    me.short_id,
                    name="overrun.bin",
                    size=1,
                    blob=blob_hex,
                )
                await channel.send(encode_msg(offer))
                await _recv_non_caps(channel)
                chunk = make_msg(
                    "FILE_CHUNK",
                    me.short_id,
                    blob=blob_hex,
                    seq=0,
                    data=base64.b64encode(content).decode("ascii"),
                    eof=True,
                )
                await channel.send(encode_msg(chunk))
            finally:
                await channel.close()

        asyncio.run(_attack())
        time.sleep(0.5)
        assert inbox_files(p.b.home) == []


# ─────────────────── Frame-size / oversize attacks ─────────────────


@pytest.mark.live_daemon
def test_oversize_frame_header_drops_connection():
    """Send a frame whose declared length exceeds MAX_FRAME. The daemon's
    read_frame must raise; we expect the connection to be closed cleanly
    without crashing the daemon."""
    with daemon_pair(pin_trust=True) as p:
        # Open a raw TCP to the peer port and send 4-byte header for 1 GB.
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", p.b.peer_port))
        try:
            s.sendall((1024 * 1024 * 1024).to_bytes(4, "big"))
            # The daemon should close on us. recv() should return b'' or error.
            try:
                # Allow some time for the daemon to log + close.
                s.settimeout(3)
                _ = s.recv(1)
            except (ConnectionResetError, OSError, TimeoutError):
                pass
        finally:
            s.close()

        # Daemon must still be alive and serving:
        from tests.harness import request

        ok = request(p.b.control_port, cmd="peers")
        assert ok["ok"]


@pytest.mark.live_daemon
def test_garbage_handshake_drops_connection():
    """Open a connection and send random bytes instead of a HELLO. Daemon
    must reject the connection without crashing."""
    with daemon_pair(pin_trust=True) as p:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect(("127.0.0.1", p.b.peer_port))
        try:
            # Send a frame of garbage. Length first.
            payload = b"\x00" * 200
            s.sendall(len(payload).to_bytes(4, "big") + payload)
            try:
                s.settimeout(2)
                s.recv(1)
            except (ConnectionResetError, OSError, TimeoutError):
                pass
        finally:
            s.close()

        from tests.harness import request

        ok = request(p.b.control_port, cmd="peers")
        assert ok["ok"]


@pytest.mark.live_daemon
def test_truncated_handshake_drops_connection():
    """Connect and immediately close, mid-handshake. Daemon must not leak."""
    with daemon_pair(pin_trust=True) as p:
        for _ in range(5):  # several abrupt connect/close cycles
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            try:
                s.connect(("127.0.0.1", p.b.peer_port))
                s.close()
            except OSError:
                pass

        from tests.harness import request

        ok = request(p.b.control_port, cmd="peers")
        assert ok["ok"]
