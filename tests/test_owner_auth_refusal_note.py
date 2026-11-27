"""What the daemon records when it refuses an owner request.

On 2026-11-25 an open window was answered 401 after a daemon restart and the
daemon's log said nothing about it. Whether the window had presented a
per-process owner token (which is meant to die with the process) or a
persistent session (which is meant to survive) decided what kind of defect it
was, and that could not be recovered afterwards. It took a real-browser
reproduction to find that every restart was invalidating every stored session.

One line now answers the question at the time. These tests pin what it says,
what it must never contain, how often it may appear, and that it cannot change
the answer the client gets.
"""

from __future__ import annotations

import logging
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.server import UIServer
from one_link.state import State

_NOTE = "owner request refused (401)"


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes_raw()
    return Identity(
        private=sk, public=sk.public_key(), public_bytes=pub,
        fingerprint=fingerprint_of(pub), short_id=fingerprint_of(pub)[:8],
        hostname="note-host",
    )


@pytest_asyncio.fixture
async def ctx(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(_identity())
    daemon.state = state
    daemon.discovery = MagicMock()
    daemon.discovery.registry = MagicMock()
    daemon.discovery.registry.list = MagicMock(return_value=[])
    server = UIServer(daemon)
    client = TestClient(TestServer(server.app))
    await client.start_server()
    try:
        yield {"client": client, "server": server, "state": state, "token": server.token}
    finally:
        await client.close()
        state.close()


def _notes(caplog) -> list[str]:
    return [record.getMessage() for record in caplog.records if _NOTE in record.getMessage()]


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_a_refused_session_is_named_as_a_session_without_recording_it(ctx, caplog):
    session = ctx["state"].create_ui_session()["session_uuid"]
    assert ctx["state"].revoke_ui_session(session) is True
    fingerprint_in_url = "f" * 64

    with caplog.at_level(logging.INFO, logger="one_link.server"):
        response = await ctx["client"].get(
            f"/api/peers/{fingerprint_in_url}/sas", headers=_bearer(session),
        )
    assert response.status == 401

    notes = _notes(caplog)
    assert len(notes) == 1
    note = notes[0]
    assert "presented=header" in note and "shape=session" in note and "transport_ok=True" in note
    # The route pattern, not the URL: a peer fingerprint is not copied into the log.
    assert "GET /api/peers/{fp}/sas" in note
    assert fingerprint_in_url not in note
    # Never the credential, whole or in part.
    everything = "\n".join(record.getMessage() for record in caplog.records)
    assert session not in everything
    assert session[:16] not in everything and session[-16:] not in everything
    assert State.ui_session_token_id(session) not in everything


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "presented", "shape"),
    [
        ({}, "none", "none"),
        (_bearer("not-a-session-bearer-but-well-formed"), "header", "other"),
        (_bearer("0" * 64), "header", "session"),
    ],
)
async def test_the_note_says_where_a_credential_was_presented_and_its_shape(
    ctx, caplog, headers, presented, shape,
):
    with caplog.at_level(logging.INFO, logger="one_link.server"):
        response = await ctx["client"].get("/api/me", headers=headers)
    assert response.status == 401
    notes = _notes(caplog)
    assert len(notes) == 1
    assert f"GET /api/me presented={presented} shape={shape} " in notes[0]


@pytest.mark.asyncio
async def test_a_valid_request_leaves_no_note(ctx, caplog):
    session = ctx["state"].create_ui_session()["session_uuid"]
    with caplog.at_level(logging.INFO, logger="one_link.server"):
        for token in (ctx["token"], session):
            response = await ctx["client"].get("/api/me", headers=_bearer(token))
            assert response.status == 200
    assert _notes(caplog) == []


@pytest.mark.asyncio
async def test_one_note_a_minute_per_client_and_every_refusal_still_counts(ctx, caplog):
    server = ctx["server"]
    with caplog.at_level(logging.INFO, logger="one_link.server"):
        for _ in range(5):
            response = await ctx["client"].get("/api/me", headers=_bearer("1" * 64))
            assert response.status == 401
    assert len(_notes(caplog)) == 1, "a window retrying with a dead credential must not flood the log"

    # The note has its own bucket: it must not consume, or hide, attempts
    # from the limit that protects the owner token.
    failures = [bucket for (name, _key), bucket in server._rate_buckets.items() if name == "auth_fail"]
    assert [len(bucket) for bucket in failures] == [5]
    noted = [bucket for (name, _key), bucket in server._rate_buckets.items() if name == "auth_refusal_note"]
    assert [len(bucket) for bucket in noted] == [1]


@pytest.mark.asyncio
async def test_a_note_that_cannot_be_written_does_not_change_the_answer(ctx, monkeypatch):
    import one_link.server as server_module

    real_info = server_module.log.info

    def refuse_to_log(message, *args, **kwargs):
        if _NOTE in str(message):
            raise RuntimeError("log sink is gone")
        return real_info(message, *args, **kwargs)

    monkeypatch.setattr(server_module.log, "info", refuse_to_log)
    response = await ctx["client"].get("/api/me", headers=_bearer("2" * 64))
    assert response.status == 401
    assert (await response.json()) == {"error": "unauthorized"}
    # And a valid request is unaffected.
    assert (await ctx["client"].get("/api/me", headers=_bearer(ctx["token"]))).status == 200


@pytest.mark.asyncio
async def test_a_refused_event_socket_is_noted_as_a_websocket_credential(ctx, caplog):
    from one_link.server import OWNER_WS_BEARER_PROTOCOL_PREFIX, OWNER_WS_PROTOCOL

    session = ctx["state"].create_ui_session()["session_uuid"]
    assert ctx["state"].revoke_ui_session(session) is True
    with caplog.at_level(logging.INFO, logger="one_link.server"):
        socket = await ctx["client"].ws_connect(
            "/api/events",
            protocols=(OWNER_WS_PROTOCOL, f"{OWNER_WS_BEARER_PROTOCOL_PREFIX}{session}"),
        )
        message = await socket.receive(timeout=5)
        # The daemon accepts the socket and closes it with 4401; it sends no
        # greeting. The owner page relies on exactly this to tell a refused
        # credential from a connection (tests/js/test_window_link.cjs).
        assert socket.close_code == 4401
        assert message.data != '{"type": "hello"}' and "hello" not in str(message.data)
        await socket.close()
    notes = _notes(caplog)
    assert len(notes) == 1
    assert "GET /api/events presented=websocket shape=session" in notes[0]
    assert session not in notes[0]


@pytest.mark.asyncio
async def test_an_authenticated_event_socket_is_greeted_first(ctx):
    """The other half of the contract the page relies on: a socket the daemon
    has authenticated receives ``hello`` as its first message."""
    from one_link.server import OWNER_WS_BEARER_PROTOCOL_PREFIX, OWNER_WS_PROTOCOL

    session = ctx["state"].create_ui_session()["session_uuid"]
    socket = await ctx["client"].ws_connect(
        "/api/events",
        protocols=(OWNER_WS_PROTOCOL, f"{OWNER_WS_BEARER_PROTOCOL_PREFIX}{session}"),
    )
    try:
        first = await socket.receive_json(timeout=5)
        assert first["type"] == "hello"
        assert socket.close_code is None
    finally:
        await socket.close()
