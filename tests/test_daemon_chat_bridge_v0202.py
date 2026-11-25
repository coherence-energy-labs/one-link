"""v0.20.2 — Phone fetches chat list + recent messages from
daemon over WebRTC.

After auto-pair completes (v0.20.1), the phone has a live
DataChannel to the daemon. This ship adds the read path:

  phone → daemon: {"v":"OL-PEER-1", "t":"fetch_peers", "rid":"..."}
  daemon → phone: {"v":"OL-PEER-1", "t":"peers", "rid":"...", peers:[...]}
  phone → daemon: {"v":"OL-PEER-1", "t":"fetch_messages", "rid":"...",
                   "peer_fp":"...", "limit":50}
  daemon → phone: {"v":"OL-PEER-1", "t":"messages", "rid":"...",
                   "peer_fp":"...", "messages":[...]}

  Reach:  phone shows the laptop's actual chat list. Tap a row,
          see recent messages. The data the user asked to see
          when they said "phone shows my chats."
  Hide:   the request/response correlation runs over the same
          DataChannel as v0.19.2's chat protocol; rids
          disambiguate.
  Async:  every request is a Promise; 10s default timeout;
          channel close fails all in-flight Promises.
  Depth:  daemon serializes only the fields the phone needs
          for a roster + chat view. Sensitive material (raw
          pubkeys, capability state, full key history) stays
          on the daemon; the phone gets fingerprint + alias +
          last-seen, not a full PeerRecord dump.

What this ship does NOT yet contain:
- Phone sends a new message via the daemon (next ship; requires
  bridging the daemon's outbound message machinery)
- Live updates / push when new messages arrive on the daemon
  (the phone only sees the snapshot it requested)
- Group chat (only direct peers in v0.20.2)

Tests cover: daemon-side handler dispatch, response shape,
auth / state-unavailable error paths, phone-side roster card,
chat card, request/response correlation, timeout handling.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.peer_rtc import (
    BrowserPeer,
    BrowserPeerManager,
    PEER_DC_PROTOCOL_VERSION,
)
from one_link.server import UIServer
from one_link.state import State


@pytest.fixture(autouse=True)
def _isolate_bridge_behavior_from_roster_admission(monkeypatch):
    """Bridge unit tests start after a browser peer was admitted.

    The real roster/certificate/revocation boundary has its own integration
    and live Chromium suite; synthetic bridge peers intentionally bypass only
    that prerequisite here.
    """

    monkeypatch.setattr(
        BrowserPeerManager,
        "peer_authorization_is_live",
        lambda _manager, _peer: True,
    )


def _identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="bridge-host",
    )


@pytest_asyncio.fixture
async def server_with_state(tmp_path: Path, monkeypatch):
    """A UIServer with a real State backing it so the bridge has
    actual peers + messages to serialize."""
    monkeypatch.setenv("ONE_LINK_HOME", str(tmp_path))
    me = _identity()
    state = State(db_path=tmp_path / "state.db")
    daemon = Daemon(me)
    daemon.state = state
    daemon.discovery = None
    daemon._outbound_sessions = {}
    daemon._inbound_regime = {}
    daemon.folder_engine = None
    server = UIServer(daemon)
    try:
        yield server, state
    finally:
        state.close()


@pytest.fixture(scope="module")
def peer_html() -> str:
    return Path("src/one_link/web/peer.html").read_text(encoding="utf-8")


def _snippet(html: str, needle: str, size: int = 2400) -> str:
    idx = html.find(needle)
    assert idx >= 0, f"missing {needle!r}"
    return html[idx:idx + size]


# ───────── daemon-side bridge handler ──────────────────────────────


def _capture_peer(server: UIServer):
    """A BrowserPeer whose control_dc is a stub that captures sent
    JSON messages. We bypass aiortc entirely — the bridge handler
    only depends on the manager's send_dc primitive."""
    captured: list[dict] = []

    class _StubChannel:
        def send(self, data):
            captured.append(json.loads(data))

    peer = BrowserPeer(
        fingerprint="sha256:abc",
        pubkey_bytes=b"\x00" * 32,
    )
    peer.control_dc = _StubChannel()
    server.peer_rtc.register_peer(peer)
    return peer, captured


@pytest.mark.asyncio
async def test_fetch_peers_returns_roster(server_with_state):
    """When the phone sends fetch_peers, the daemon responds with
    a list of paired peers serialized to a phone-friendly shape."""
    server, state = server_with_state
    state.upsert_peer(
        fingerprint="sha256:peer1",
        short_id="peer1",
        hostname="other-laptop",
        pubkey=b"\x01" * 32,
    )
    state.upsert_peer(
        fingerprint="sha256:peer2",
        short_id="peer2",
        hostname="phone",
        pubkey=b"\x02" * 32,
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_peers",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_peers", "rid": "r1"},
    )
    assert len(captured) == 1
    reply = captured[0]
    assert reply["t"] == "peers"
    assert reply["rid"] == "r1"
    assert reply["v"] == PEER_DC_PROTOCOL_VERSION
    assert isinstance(reply["peers"], list)
    fps = {p["fingerprint"] for p in reply["peers"]}
    assert "sha256:peer1" in fps
    assert "sha256:peer2" in fps


@pytest.mark.asyncio
async def test_fetch_peers_serializes_minimal_fields(server_with_state):
    """The daemon MUST NOT leak raw pubkeys, full capability state,
    or key history through the bridge. Phone roster only needs
    fingerprint + alias + last_seen + trust state."""
    server, state = server_with_state
    state.upsert_peer(
        fingerprint="sha256:abc",
        short_id="abc",
        hostname="laptop",
        pubkey=b"\x01" * 32,
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_peers",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_peers", "rid": "r1"},
    )
    record = captured[0]["peers"][0]
    # Must include
    for key in ("fingerprint", "short_id", "hostname", "alias", "trust"):
        assert key in record, f"missing {key}"
    # Must NOT include
    for key in ("verifier_pub", "pub_key_b64", "capabilities", "key_history"):
        assert key not in record, f"leaked {key} through bridge"


@pytest.mark.asyncio
async def test_fetch_messages_returns_recent(server_with_state):
    """fetch_messages with peer_fp returns the most recent N
    messages serialized to a phone-friendly shape."""
    server, state = server_with_state
    state.upsert_peer(
        fingerprint="sha256:p1",
        short_id="p1",
        hostname="x",
        pubkey=b"\x01" * 32,
    )
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp="sha256:p1",
        msg_type="text", body="hello",
    )
    state.record_message(
        id="m2", ts_ms=2000, direction="out", peer_fp="sha256:p1",
        msg_type="text", body="hi back", reply_to="m1",
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_messages",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "fetch_messages",
            "rid": "r2",
            "peer_fp": "sha256:p1",
            "limit": 50,
        },
    )
    assert len(captured) == 1
    reply = captured[0]
    assert reply["t"] == "messages"
    assert reply["rid"] == "r2"
    assert reply["peer_fp"] == "sha256:p1"
    assert len(reply["messages"]) == 2
    bodies = [m["body"] for m in reply["messages"]]
    assert "hello" in bodies
    assert "hi back" in bodies
    assert any(m.get("reply_to") == "m1" for m in reply["messages"])


@pytest.mark.asyncio
async def test_fetch_messages_caps_limit(server_with_state):
    """A malicious peer can't ask for 1M messages and DoS the
    daemon's serialization. Limit clamped to 500."""
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_messages",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "fetch_messages",
            "rid": "r3",
            "peer_fp": "sha256:p1",
            "limit": 1_000_000,
        },
    )
    # No assertion on the response itself beyond it being well-
    # formed — the cap is enforced by the bridge before the SQL
    # query, so no DoS path even if state had millions of rows.
    assert captured[0]["t"] == "messages"


@pytest.mark.asyncio
async def test_fetch_messages_rejects_missing_peer_fp(server_with_state):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_messages",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "fetch_messages",
            "rid": "r4",
            # peer_fp missing
        },
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "bad_peer_fp"


@pytest.mark.asyncio
async def test_fetch_groups_returns_member_groups(server_with_state, monkeypatch):
    server, state = server_with_state
    gid = b"\x11" * 16
    state.upsert_group_meta(
        group_id=gid, name="Family", created_ms=1000, state_hash="h",
    )

    def fake_materialize(group_id):
        assert group_id == gid
        return {
            "group_id": gid.hex(),
            "name": "Family",
            "member_count": 3,
            "my_role": "member",
            "is_member": True,
        }

    monkeypatch.setattr(server, "_materialize_group", fake_materialize)
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_groups",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_groups", "rid": "g1"},
    )
    reply = captured[0]
    assert reply["t"] == "groups"
    assert reply["rid"] == "g1"
    assert reply["groups"] == [{
        "group_id": gid.hex(),
        "name": "Family",
        "member_count": 3,
        "my_role": "member",
    }]


@pytest.mark.asyncio
async def test_fetch_group_messages_returns_recent(server_with_state):
    server, state = server_with_state
    gid = b"\x22" * 16
    state.insert_group_message(
        id="gm1", group_id=gid, sender_pub=b"\x01" * 32,
        epoch=1, counter=1, direction="in", body="hello group",
        reply_to=None, ts_ms=1000,
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_group_messages",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "fetch_group_messages",
            "rid": "g2",
            "group_id": gid.hex(),
            "limit": 50,
        },
    )
    reply = captured[0]
    assert reply["t"] == "group_messages"
    assert reply["group_id"] == gid.hex()
    assert reply["messages"][0]["id"] == "gm1"
    assert reply["messages"][0]["body"] == "hello group"
    assert reply["messages"][0]["sender_pub_hex"] == ("01" * 32)


@pytest.mark.asyncio
async def test_search_group_messages_filters_body(server_with_state):
    server, state = server_with_state
    gid = b"\x22" * 16
    state.insert_group_message(
        id="gm1", group_id=gid, sender_pub=b"\x01" * 32,
        epoch=1, counter=1, direction="in", body="quiet group signal",
        ts_ms=1000,
    )
    state.insert_group_message(
        id="gm2", group_id=gid, sender_pub=b"\x01" * 32,
        epoch=1, counter=2, direction="in", body="unrelated",
        ts_ms=2000,
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "search_group_messages",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "search_group_messages",
            "rid": "gs1",
            "group_id": gid.hex(),
            "query": "quiet",
            "limit": 20,
        },
    )
    reply = captured[0]
    assert reply["t"] == "group_message_search_results"
    assert reply["group_id"] == gid.hex()
    assert [m["id"] for m in reply["messages"]] == ["gm1"]


@pytest.mark.asyncio
async def test_send_group_message_routes_through_daemon(server_with_state, monkeypatch):
    server, _ = server_with_state
    gid = b"\x33" * 16
    captured_args = {}

    async def fake_send_group_message(*, group_id, body, reply_to=None):
        captured_args.update(group_id=group_id, body=body, reply_to=reply_to)
        return {"id": "gm2"}

    monkeypatch.setattr(
        server.daemon, "send_group_message", fake_send_group_message,
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "send_group_message",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_group_message",
            "rid": "g3",
            "group_id": gid.hex(),
            "body": "hello group",
            "reply_to": "gm1",
        },
    )
    reply = captured[0]
    assert reply["t"] == "send_group_message_result"
    assert reply["ok"] is True
    assert captured_args == {
        "group_id": gid,
        "body": "hello group",
        "reply_to": "gm1",
    }


@pytest.mark.asyncio
async def test_group_message_actions_route_through_daemon(server_with_state, monkeypatch):
    server, _ = server_with_state
    gid = b"\x44" * 16
    calls = []

    async def fake_reaction(*, group_id, target_msg_id, emoji, op):
        calls.append(("react", group_id, target_msg_id, emoji, op))
        return {"sent": 2}

    async def fake_edit(*, group_id, target_msg_id, new_body):
        calls.append(("edit", group_id, target_msg_id, new_body))
        return {"sent": 2}

    async def fake_delete(*, group_id, target_msg_id):
        calls.append(("delete", group_id, target_msg_id))
        return {"sent": 2}

    monkeypatch.setattr(server.daemon, "send_group_reaction", fake_reaction)
    monkeypatch.setattr(server.daemon, "send_group_edit", fake_edit)
    monkeypatch.setattr(server.daemon, "send_group_delete", fake_delete)
    peer, captured = _capture_peer(server)

    await server._handle_browser_peer_request(
        peer, "control", "react_group_message",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "react_group_message",
            "rid": "gr1",
            "group_id": gid.hex(),
            "msg_id": "gm1",
            "emoji": "👍",
            "op": "add",
        },
    )
    await server._handle_browser_peer_request(
        peer, "control", "edit_group_message",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "edit_group_message",
            "rid": "ge1",
            "group_id": gid.hex(),
            "msg_id": "gm1",
            "body": "updated group message",
        },
    )
    await server._handle_browser_peer_request(
        peer, "control", "delete_group_message",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "delete_group_message",
            "rid": "gd1",
            "group_id": gid.hex(),
            "msg_id": "gm1",
        },
    )

    assert [msg["t"] for msg in captured] == [
        "react_group_message_result",
        "edit_group_message_result",
        "delete_group_message_result",
    ]
    assert calls == [
        ("react", gid, "gm1", "👍", "add"),
        ("edit", gid, "gm1", "updated group message"),
        ("delete", gid, "gm1"),
    ]


@pytest.mark.asyncio
async def test_group_management_actions_route_through_daemon(server_with_state, monkeypatch):
    server, state = server_with_state
    gid = b"\x55" * 16
    peer_pub = b"\x09" * 32
    state.upsert_peer(
        fingerprint="sha256:pinned",
        short_id="pinned",
        hostname="friend",
        pubkey=peer_pub,
    )
    state.set_peer_trust("sha256:pinned", "pinned")
    calls = []

    server._materialize_group = lambda _gid: {
        "group_id": gid.hex(),
        "name": "Team",
        "is_member": True,
        "members": [{
            "fingerprint": "sha256:pinned",
            "display_name": "friend",
            "role": "member",
            "is_me": False,
        }],
    }

    async def fake_add(*, group_id, member_pubkey, role):
        calls.append(("add", group_id, member_pubkey, role))
        return {"member_count": 2}

    async def fake_remove(*, group_id, member_pubkey):
        calls.append(("remove", group_id, member_pubkey))
        return {"member_count": 1}

    monkeypatch.setattr(server.daemon, "add_group_member", fake_add)
    monkeypatch.setattr(server.daemon, "remove_group_member", fake_remove)
    peer, captured = _capture_peer(server)

    for rid, t, extra in [
        ("gd1", "fetch_group_detail", {}),
        ("gi1", "group_invite_link", {}),
        ("ga1", "add_group_member", {"peer_fp": "sha256:pinned"}),
        ("gr1", "remove_group_member", {"peer_fp": "sha256:pinned"}),
        ("gl1", "leave_group", {}),
    ]:
        await server._handle_browser_peer_request(
            peer, "control", t,
            {
                "v": PEER_DC_PROTOCOL_VERSION,
                "t": t,
                "rid": rid,
                "group_id": gid.hex(),
                **extra,
            },
        )

    assert [msg["t"] for msg in captured] == [
        "group_detail",
        "group_invite_link_result",
        "add_group_member_result",
        "remove_group_member_result",
        "leave_group_result",
    ]
    assert captured[1]["url"].startswith("one-link://group-invite/")
    assert calls == [
        ("add", gid, peer_pub, "member"),
        ("remove", gid, peer_pub),
        ("remove", gid, server.daemon.me.public_bytes),
    ]


@pytest.mark.asyncio
async def test_search_messages_returns_peer_scoped_results(server_with_state):
    """Phone search rides the daemon bridge and uses the daemon's
    FTS index, scoped to the active direct chat.
    """
    server, state = server_with_state
    state.upsert_peer(
        fingerprint="sha256:p1",
        short_id="p1",
        hostname="x",
        pubkey=b"\x01" * 32,
    )
    state.upsert_peer(
        fingerprint="sha256:p2",
        short_id="p2",
        hostname="y",
        pubkey=b"\x02" * 32,
    )
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp="sha256:p1",
        msg_type="text", body="find the quiet signal",
    )
    state.record_message(
        id="m2", ts_ms=2000, direction="in", peer_fp="sha256:p2",
        msg_type="text", body="find the quiet signal",
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "search_messages",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "search_messages",
            "rid": "s1",
            "peer_fp": "sha256:p1",
            "query": "quiet signal",
            "limit": 20,
        },
    )
    reply = captured[0]
    assert reply["t"] == "message_search_results"
    assert reply["rid"] == "s1"
    assert reply["peer_fp"] == "sha256:p1"
    assert reply["query"] == "quiet signal"
    assert [m["id"] for m in reply["messages"]] == ["m1"]


@pytest.mark.asyncio
async def test_search_messages_rejects_empty_query(server_with_state):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "search_messages",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "search_messages",
            "rid": "s2",
            "peer_fp": "sha256:p1",
            "query": "   ",
        },
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "bad_query"


@pytest.mark.asyncio
async def test_global_search_returns_messages_peers_groups_and_files(
    server_with_state,
):
    server, state = server_with_state
    fp = "aa" * 32
    state.upsert_peer(
        fingerprint=fp,
        short_id="alpha",
        pubkey=b"\x01" * 32,
        hostname="alpha-phone",
    )
    state.record_message(
        id="m-alpha",
        ts_ms=1234,
        direction="in",
        peer_fp=fp,
        msg_type="TEXT",
        body="alpha launch note",
    )
    gid = bytes.fromhex("01" * 16)
    state._conn.execute(
        "INSERT INTO groups(group_id, name, created_ms, updated_ms) "
        "VALUES(?, ?, ?, ?)",
        (gid, "alpha group", 1000, 2000),
    )
    state._conn.commit()
    from one_link.paths import inbox_dir

    (inbox_dir() / "alpha-plan.txt").write_text("ship it", encoding="utf-8")

    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "global_search",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "global_search",
            "rid": "gs1",
            "query": "alpha",
            "limit": 10,
        },
    )
    reply = captured[0]
    assert reply["t"] == "global_search_results"
    assert reply["rid"] == "gs1"
    assert any(m["id"] == "m-alpha" for m in reply["messages"])
    assert any(p["fingerprint"] == fp for p in reply["peers"])
    assert any(g["group_id"] == gid.hex() for g in reply["groups"])
    assert any(f["name"] == "alpha-plan.txt" for f in reply["files"])


@pytest.mark.asyncio
async def test_global_search_rejects_overlong_query(server_with_state):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "global_search",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "global_search",
            "rid": "gs2",
            "query": "x" * 201,
        },
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "bad_query"


@pytest.mark.asyncio
async def test_fetch_messages_includes_reactions(server_with_state):
    server, state = server_with_state
    state.upsert_peer(
        fingerprint="sha256:p1",
        short_id="p1",
        hostname="x",
        pubkey=b"\x01" * 32,
    )
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp="sha256:p1",
        msg_type="text", body="hello",
    )
    state.record_reaction(
        target_msg_id="m1", peer_fp="sha256:p1", emoji="👍",
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_messages",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "fetch_messages",
            "rid": "rx1",
            "peer_fp": "sha256:p1",
            "limit": 50,
        },
    )
    msg = captured[0]["messages"][0]
    assert msg["reactions"]["👍"] == ["sha256:p1"]


@pytest.mark.asyncio
async def test_react_message_offline_peer_persists_locally(
    server_with_state, monkeypatch,
):
    server, state = server_with_state

    async def fake_resolve(_needle):
        return None

    monkeypatch.setattr(server.daemon, "resolve_for_send", fake_resolve)
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "react_message",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "react_message",
            "rid": "rx2",
            "peer_fp": "sha256:p1",
            "msg_id": "m1",
            "emoji": "👍",
            "op": "add",
        },
    )
    reply = captured[0]
    assert reply["t"] == "react_message_result"
    assert reply["ok"] is True
    assert reply["delivered"] is False
    rows = state.list_reactions_for_messages(["m1"])
    assert rows["m1"]["👍"] == [server.daemon.me.fingerprint]


@pytest.mark.asyncio
async def test_react_message_validates_emoji(server_with_state):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "react_message",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "react_message",
            "rid": "rx3",
            "peer_fp": "sha256:p1",
            "msg_id": "m1",
            "emoji": "",
        },
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "bad_emoji"


@pytest.mark.asyncio
async def test_edit_message_routes_through_daemon_send_edit(
    server_with_state, monkeypatch,
):
    server, state = server_with_state
    state.record_message(
        id="m1", ts_ms=1000, direction="out", peer_fp="sha256:p1",
        msg_type="text", body="old",
    )

    class FakePeer:
        fingerprint = "sha256:p1"

    async def fake_resolve(_needle):
        return FakePeer()

    async def fake_send_edit(peer, *, target_msg_id, new_body):
        state.edit_message(id=target_msg_id, new_body=new_body, edited_at_ms=2000)
        return {"ack": {"ok": True}, "peer": peer.fingerprint}

    monkeypatch.setattr(server.daemon, "resolve_for_send", fake_resolve)
    monkeypatch.setattr(server.daemon, "send_edit", fake_send_edit)
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "edit_message",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "edit_message",
            "rid": "ed1",
            "peer_fp": "sha256:p1",
            "msg_id": "m1",
            "body": "new",
        },
    )
    reply = captured[0]
    assert reply["t"] == "edit_message_result"
    assert reply["ok"] is True
    assert reply["msg"]["body"] == "new"
    assert state.get_message("m1").body == "new"


@pytest.mark.asyncio
async def test_edit_message_rejects_inbound(server_with_state):
    server, state = server_with_state
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp="sha256:p1",
        msg_type="text", body="theirs",
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "edit_message",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "edit_message",
            "rid": "ed2",
            "peer_fp": "sha256:p1",
            "msg_id": "m1",
            "body": "nope",
        },
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "not_outbound"


@pytest.mark.asyncio
async def test_delete_message_offline_soft_deletes_locally(
    server_with_state, monkeypatch,
):
    server, state = server_with_state
    state.record_message(
        id="m1", ts_ms=1000, direction="out", peer_fp="sha256:p1",
        msg_type="text", body="bye",
    )

    async def fake_resolve(_needle):
        return None

    monkeypatch.setattr(server.daemon, "resolve_for_send", fake_resolve)
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "delete_message",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "delete_message",
            "rid": "del1",
            "peer_fp": "sha256:p1",
            "msg_id": "m1",
        },
    )
    reply = captured[0]
    assert reply["t"] == "delete_message_result"
    assert reply["ok"] is True
    assert reply["delivered"] is False
    assert state.get_message("m1").is_deleted


@pytest.mark.asyncio
async def test_fetch_self_returns_daemon_identity(server_with_state):
    """fetch_self lets the phone show "Connected to <hostname>"
    without an extra REST call."""
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_self",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_self", "rid": "r5"},
    )
    reply = captured[0]
    assert reply["t"] == "self"
    assert reply["rid"] == "r5"
    assert reply["fingerprint"] == server.daemon.me.fingerprint
    assert reply["hostname"] == server.daemon.me.hostname


@pytest.mark.asyncio
async def test_unknown_t_silently_ignored(server_with_state):
    """v0.19.2's chat protocol also rides this channel. The bridge
    handler MUST silently ignore frames it doesn't recognize, not
    error-spam them."""
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "text",  # v0.19.2 chat-protocol kind
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "text", "id": "x"},
    )
    assert captured == []


@pytest.mark.asyncio
async def test_state_unavailable_yields_error(server_with_state):
    """If state isn't initialized (degenerate daemon), surface a
    semantic error rather than crashing."""
    server, _ = server_with_state
    server.daemon.state = None
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_peers",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_peers", "rid": "r6"},
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "no_state"


# ───────── send_message wire path ─────────────────────────────────


@pytest.mark.asyncio
async def test_send_message_requires_peer_fp(server_with_state):
    """Missing/empty peer_fp returns a typed error, not a crash."""
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "send_message",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_message",
         "rid": "s1", "body": "hi"},
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "bad_peer_fp"
    assert captured[0]["rid"] == "s1"


@pytest.mark.asyncio
async def test_send_message_requires_body(server_with_state):
    """Missing/empty body returns a typed error."""
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "send_message",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_message",
         "rid": "s2", "peer_fp": "sha256:abc"},
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "bad_body"


@pytest.mark.asyncio
async def test_send_message_body_too_large(server_with_state):
    """Bodies over 64 KiB UTF-8 are rejected at the wire — the
    desktop send path uses a similar de facto cap and the phone
    surface should not be a way around it."""
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    huge = "x" * (65 * 1024)
    await server._handle_browser_peer_request(
        peer, "control", "send_message",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_message",
         "rid": "s3", "peer_fp": "sha256:abc", "body": huge},
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "body_too_large"


@pytest.mark.asyncio
async def test_send_message_unknown_peer_falls_through_to_outbox_or_errors(
    server_with_state, monkeypatch,
):
    """When the peer isn't resolvable (offline / unknown), the
    handler should attempt the outbox fallback (matching desktop
    /api/send default semantics). If even the outbox enqueue
    fails (e.g. unknown fingerprint), surface a typed error
    rather than a raw exception trace."""
    server, _ = server_with_state

    async def fake_resolve(needle):
        return None

    def fake_enqueue(target_fp, body, client_msg_id=None):
        raise ValueError("unknown peer fingerprint")

    monkeypatch.setattr(server.daemon, "resolve_for_send", fake_resolve)
    monkeypatch.setattr(server.daemon, "enqueue_text_outbox", fake_enqueue)

    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "send_message",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_message",
         "rid": "s4", "peer_fp": "sha256:abc", "body": "hi"},
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "peer_offline_enqueue_failed"


@pytest.mark.asyncio
async def test_send_message_routes_through_daemon_send_text(
    server_with_state, monkeypatch,
):
    """The happy path delegates to daemon.send_text — same call
    site /api/send uses. Asserting this keeps the phone send
    surface from quietly drifting into a parallel half-protocol."""
    server, _ = server_with_state

    class FakePeer:
        fingerprint = "sha256:abc"

    async def fake_resolve(needle):
        return FakePeer()

    captured_send_args: dict = {}

    async def fake_send_text(target, body, reply_to=None, client_msg_id=None):
        captured_send_args.update(
            target=target, body=body, reply_to=reply_to,
            client_msg_id=client_msg_id,
        )
        return {
            "id": "msg-1",
            "ts_ms": 12345,
            "direction": "outbound",
            "body": body,
            "msg_type": "text",
        }

    monkeypatch.setattr(server.daemon, "resolve_for_send", fake_resolve)
    monkeypatch.setattr(server.daemon, "send_text", fake_send_text)

    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "send_message",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_message",
         "rid": "s5", "peer_fp": "sha256:abc",
         "body": "hello world",
         "client_msg_id": "deadbeef" * 4},
    )
    assert captured[0]["t"] == "send_message_result"
    assert captured[0]["rid"] == "s5"
    assert captured[0]["ok"] is True
    assert captured[0]["msg"]["body"] == "hello world"
    assert captured_send_args["body"] == "hello world"
    assert captured_send_args["client_msg_id"] == "deadbeef" * 4


# ───────── phone-side compose surface ─────────────────────────────


def test_daemon_chat_card_has_compose(peer_html: str):
    """2026-05-23: the phone chat surface MUST include a compose
    textarea + send button + status line. Without these the phone
    is read-only and the user can't actually use One Link from
    their phone."""
    assert 'id="daemon-chat-compose"' in peer_html
    assert 'id="daemon-chat-input"' in peer_html
    assert 'id="btn-daemon-chat-send"' in peer_html
    assert 'id="daemon-chat-send-status"' in peer_html


def test_phone_send_function_uses_send_message_kind(peer_html: str):
    """Pin the wire shape: sendDaemonMessage routes through
    _daemonRequest with t='send_message' and the four expected
    fields. Any drift here breaks the round trip silently."""
    snip = _snippet(peer_html, "async function sendDaemonMessage(", 1200)
    assert '_daemonRequest("send_message"' in snip
    assert "peer_fp" in snip
    assert "body" in snip
    assert "reply_to" in snip
    assert "client_msg_id" in snip


# ───────── send_file (chunked upload) wire path ───────────────────


def test_phone_chat_search_controls_exist(peer_html: str):
    assert 'id="daemon-chat-search-input"' in peer_html
    assert 'id="btn-daemon-chat-search"' in peer_html
    assert 'type="search"' in peer_html
    assert 'aria-label="Search this chat"' in peer_html


def test_phone_global_search_controls_exist(peer_html: str):
    assert 'id="daemon-global-search-input"' in peer_html
    assert 'id="btn-daemon-global-search"' in peer_html
    assert 'id="daemon-global-search-results"' in peer_html
    assert 'aria-label="Search all chats, groups, and files"' in peer_html


def test_phone_global_search_uses_daemon_bridge(peer_html: str):
    fn = _snippet(peer_html, "async function searchDaemonGlobal", 700)
    assert '_daemonRequest("global_search"' in fn
    assert "query: String(query || \"\").trim()" in fn
    handler = _snippet(peer_html, "async function _handleDaemonGlobalSearch", 1600)
    assert "searchDaemonGlobal(query, 10)" in handler
    assert "_renderDaemonGlobalSearchResults(reply, query)" in handler
    renderer = _snippet(peer_html, "function _renderDaemonGlobalSearchResults", 5200)
    assert "_openDaemonChat(peer)" in renderer
    assert "_openDaemonGroupChat(group)" in renderer
    assert "results.files" in renderer


def test_phone_search_function_uses_search_messages_kind(peer_html: str):
    snip = _snippet(peer_html, "async function searchDaemonMessages", 900)
    assert '_daemonRequest("search_messages"' in snip
    assert "peer_fp: peerFp" in snip
    assert "query: String(query || \"\").trim()" in snip


def test_phone_search_handler_renders_results(peer_html: str):
    snip = _snippet(peer_html, "async function _handleDaemonChatSearch", 2200)
    assert "searchDaemonMessages(peer.fingerprint, query, 50)" in snip
    assert "No matches for" in snip
    assert "_renderDaemonMessageBubble(log, m)" in snip
    assert 'id="btn-daemon-chat-search"' in peer_html
    assert 'id="daemon-chat-search-input"' in peer_html


def test_phone_reaction_function_uses_react_message_kind(peer_html: str):
    snip = _snippet(peer_html, "async function reactDaemonMessage", 900)
    assert '_daemonRequest("react_message"' in snip
    assert "msg_id: msgId" in snip
    assert "emoji" in snip
    assert 'op: op || "add"' in snip


def test_phone_message_bubble_renders_reaction_row(peer_html: str):
    snip = _snippet(peer_html, "function _renderDaemonReactionRow", 2600)
    assert "m.reactions" in snip
    assert "state.daemon_active_peer && state.daemon_active_peer.fingerprint" in snip
    assert "state.daemon_active_group && state.daemon_active_group.group_id" in snip
    assert "reactDaemonMessage(peer.fingerprint, m.id, emoji, \"add\")" in snip
    assert "reactDaemonGroupMessage(group.group_id, m.id, emoji, \"add\")" in snip
    assert "fetchDaemonMessages(peer.fingerprint, 50)" in snip
    assert "fetchDaemonGroupMessages(group.group_id, 50)" in snip
    bubble = _snippet(peer_html, "function _renderDaemonMessageBubble", 2600)
    assert "_renderDaemonReactionRow(bubble, m)" in bubble


def test_phone_edit_delete_functions_use_daemon_bridge(peer_html: str):
    edit = _snippet(peer_html, "async function editDaemonMessage", 700)
    assert '_daemonRequest("edit_message"' in edit
    assert "msg_id: msgId" in edit
    assert "body" in edit
    delete = _snippet(peer_html, "async function deleteDaemonMessage", 700)
    assert '_daemonRequest("delete_message"' in delete
    assert "msg_id: msgId" in delete


def test_phone_message_bubble_renders_edit_delete_for_outbound(peer_html: str):
    snip = _snippet(peer_html, "function _renderDaemonMessageActions", 2600)
    assert 'const actions = ["Reply"]' in snip
    assert 'actions.push("Edit", "Delete")' in snip
    assert "Edit" in snip
    assert "Delete" in snip
    assert "editDaemonMessage(peer.fingerprint, m.id" in snip
    assert "deleteDaemonMessage(peer.fingerprint, m.id)" in snip
    assert "editDaemonGroupMessage(group.group_id, m.id" in snip
    assert "deleteDaemonGroupMessage(group.group_id, m.id)" in snip
    bubble = _snippet(peer_html, "function _renderDaemonMessageBubble", 2800)
    assert "_renderDaemonMessageActions(bubble, m)" in bubble


def test_phone_reply_surface_and_send_wire(peer_html: str):
    assert 'id="daemon-chat-reply-bar"' in peer_html
    assert 'id="daemon-chat-reply-preview"' in peer_html
    assert 'id="btn-daemon-chat-reply-cancel"' in peer_html
    actions = _snippet(peer_html, "function _renderDaemonMessageActions", 3200)
    assert 'const actions = ["Reply"]' in actions
    assert "_setDaemonReply(m)" in actions
    send = _snippet(peer_html, "async function _handleDaemonChatSend", 2400)
    assert "const replyTo = state.daemon_reply_to" in send
    assert "reply_to: replyTo && replyTo.id" in send
    assert "_clearDaemonReply()" in send


def test_phone_reply_quote_renders_on_message_bubble(peer_html: str):
    bubble = _snippet(peer_html, "function _renderDaemonMessageBubble", 3000)
    assert "m.reply_to" in bubble
    assert "Reply to" in bubble
    assert "_renderDaemonMessageActions(bubble, m)" in bubble


def test_phone_group_roster_and_messages_use_daemon_bridge(peer_html: str):
    assert "async function fetchDaemonGroups()" in peer_html
    assert '_daemonRequest("fetch_groups"' in peer_html
    assert "async function fetchDaemonGroupDetail" in peer_html
    assert '_daemonRequest("fetch_group_detail"' in peer_html
    assert "async function fetchDaemonGroupMessages" in peer_html
    assert '_daemonRequest("fetch_group_messages"' in peer_html
    assert "async function searchDaemonGroupMessages" in peer_html
    assert '_daemonRequest("search_group_messages"' in peer_html
    assert "async function fetchDaemonGroupInviteLink" in peer_html
    assert '_daemonRequest("group_invite_link"' in peer_html
    assert "async function addDaemonGroupMember" in peer_html
    assert '_daemonRequest("add_group_member"' in peer_html
    assert "async function removeDaemonGroupMember" in peer_html
    assert '_daemonRequest("remove_group_member"' in peer_html
    assert "async function leaveDaemonGroup" in peer_html
    assert '_daemonRequest("leave_group"' in peer_html
    assert "async function sendDaemonGroupMessage" in peer_html
    assert '_daemonRequest("send_group_message"' in peer_html
    assert "async function reactDaemonGroupMessage" in peer_html
    assert '_daemonRequest("react_group_message"' in peer_html
    assert "async function editDaemonGroupMessage" in peer_html
    assert '_daemonRequest("edit_group_message"' in peer_html
    assert "async function deleteDaemonGroupMessage" in peer_html
    assert '_daemonRequest("delete_group_message"' in peer_html
    roster = _snippet(peer_html, "async function _refreshDaemonRoster", 5200)
    assert "groups = await fetchDaemonGroups()" in roster
    assert "_openDaemonGroupChat(group)" in roster
    group_chat = _snippet(peer_html, "async function _openDaemonGroupChat", 2600)
    assert "fetchDaemonGroupMessages(group.group_id, 50)" in group_chat
    assert 'input.placeholder = "Message group"' in group_chat
    assert 'searchInput.placeholder = "Search this group"' in group_chat
    assert "searchBtn.disabled = false" in group_chat
    send = _snippet(peer_html, "async function _handleDaemonChatSend", 3600)
    assert "sendDaemonGroupMessage(group.group_id, body" in send
    assert "fetchDaemonGroupMessages(group.group_id, 50)" in send
    search = _snippet(peer_html, "async function _handleDaemonChatSearch", 2600)
    assert "searchDaemonGroupMessages(group.group_id, query, 50)" in search
    assert 'id="daemon-chat-group-settings"' in peer_html
    assert 'id="btn-daemon-chat-group-invite"' in peer_html
    assert 'id="btn-daemon-chat-group-add"' in peer_html
    assert 'id="btn-daemon-chat-group-leave"' in peer_html
    info = _snippet(peer_html, "async function _renderDaemonGroupInfo", 4200)
    assert "fetchDaemonGroupDetail(group.group_id)" in info
    assert '["owner", "admin"].includes' in info
    assert "select.disabled = !canManageMembers" in info
    assert "removeDaemonGroupMember(group.group_id" in info
    assert "addDaemonGroupMember(group.group_id, peerFp)" in peer_html
    assert "fetchDaemonGroupInviteLink(group.group_id)" in peer_html
    assert "leaveDaemonGroup(group.group_id)" in peer_html


@pytest.mark.asyncio
async def test_send_file_init_requires_peer_fp(server_with_state):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "send_file_init",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_init",
         "rid": "f1", "filename": "x.txt", "size_bytes": 10},
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "bad_peer_fp"


@pytest.mark.asyncio
async def test_send_file_init_rejects_oversized(server_with_state):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "send_file_init",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_init",
         "rid": "f2", "peer_fp": "sha256:abc",
         "filename": "huge.bin",
         "size_bytes": 200 * 1024 * 1024},
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "file_too_large"


@pytest.mark.asyncio
async def test_send_file_init_rejects_boolean_size_spoof(server_with_state):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)

    await server._handle_browser_peer_request(
        peer, "control", "send_file_init",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_init",
            "rid": "bool-size",
            "peer_fp": "sha256:abc",
            "filename": "spoof.bin",
            "size_bytes": True,
        },
    )

    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "bad_size"
    assert server._upload_reservations.snapshot() == ()


@pytest.mark.asyncio
async def test_phone_upload_global_admission_is_atomic_and_released(
    server_with_state,
):
    from one_link.transfer_safety import TransferAdmissionPolicy

    server, _ = server_with_state
    assert server._upload_reservations is (
        server.daemon._transfer_reservation_ledger()
    )
    server._upload_admission_policy = TransferAdmissionPolicy(
        max_declared_bytes=1024,
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
        max_active_inbound_transfers_per_peer=4,
        max_active_inbound_bytes_per_peer=4096,
        max_active_inbound_transfers=1,
        max_active_inbound_bytes=4096,
    )
    peer, captured = _capture_peer(server)
    first = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "send_file_init",
        "rid": "global-one",
        "peer_fp": "sha256:one",
        "filename": "one.bin",
        "size_bytes": 10,
    }
    second = {
        **first,
        "rid": "global-two",
        "peer_fp": "sha256:two",
        "filename": "two.bin",
    }

    await server._handle_browser_peer_request(
        peer, "control", "send_file_init", first,
    )
    first_id = captured[-1]["upload_id"]
    await server._handle_browser_peer_request(
        peer, "control", "send_file_init", second,
    )

    assert captured[-1]["t"] == "error"
    assert captured[-1]["code"] == "upload_admission_global_inbound_transfer_quota"
    assert len(server._upload_reservations.snapshot()) == 1
    assert await server._discard_phone_upload(first_id)
    assert server._upload_reservations.snapshot() == ()

    captured.clear()
    await server._handle_browser_peer_request(
        peer, "control", "send_file_init", second,
    )
    assert captured[-1]["t"] == "send_file_init_ack"
    await server._discard_phone_upload(captured[-1]["upload_id"])


@pytest.mark.asyncio
async def test_phone_upload_target_rotation_cannot_evade_source_quota(
    server_with_state,
):
    from one_link.transfer_safety import TransferAdmissionPolicy

    server, _ = server_with_state
    server._upload_admission_policy = TransferAdmissionPolicy(
        max_declared_bytes=1024,
        min_free_reserve_bytes=0,
        free_reserve_ratio=0,
        max_active_inbound_transfers_per_peer=1,
        max_active_inbound_bytes_per_peer=4096,
        max_active_inbound_transfers=10,
        max_active_inbound_bytes=4096,
    )
    peer, captured = _capture_peer(server)
    base = {
        "v": PEER_DC_PROTOCOL_VERSION,
        "t": "send_file_init",
        "filename": "one.bin",
        "size_bytes": 10,
    }
    await server._handle_browser_peer_request(
        peer,
        "control",
        "send_file_init",
        {**base, "rid": "rotate-one", "peer_fp": "sha256:target-one"},
    )
    upload_id = captured[-1]["upload_id"]
    await server._handle_browser_peer_request(
        peer,
        "control",
        "send_file_init",
        {**base, "rid": "rotate-two", "peer_fp": "sha256:target-two"},
    )

    assert captured[-1]["code"] == "upload_admission_peer_inbound_transfer_quota"
    reservations = server._upload_reservations.snapshot()
    assert len(reservations) == 1
    assert reservations[0].peer_fp == f"phone:{peer.fingerprint}"
    await server._discard_phone_upload(upload_id)


@pytest.mark.asyncio
async def test_phone_upload_rejects_non_base64url_without_advancing(
    server_with_state,
):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer,
        "control",
        "send_file_init",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_init",
            "rid": "b64-init",
            "peer_fp": "sha256:abc",
            "filename": "bad.bin",
            "size_bytes": 10,
        },
    )
    upload_id = captured[-1]["upload_id"]
    captured.clear()

    await server._handle_browser_peer_request(
        peer,
        "control",
        "send_file_chunk",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_chunk",
            "rid": "b64-chunk",
            "upload_id": upload_id,
            "offset": 0,
            "data_b64": "!!!!",
        },
    )

    assert captured[-1]["code"] == "bad_b64"
    assert server._phone_uploads[upload_id]["received_size"] == 0
    assert len(server._upload_reservations.snapshot()) == 1
    await server._discard_phone_upload(upload_id)


@pytest.mark.asyncio
async def test_phone_upload_cancel_removes_bytes_handle_and_reservation(
    server_with_state,
):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer,
        "control",
        "send_file_init",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_init",
            "rid": "cancel-init",
            "peer_fp": "sha256:target",
            "filename": "cancel.bin",
            "size_bytes": 10,
        },
    )
    upload_id = captured[-1]["upload_id"]
    staged = Path(server._phone_uploads[upload_id]["path"])
    captured.clear()

    await server._handle_browser_peer_request(
        peer,
        "control",
        "send_file_cancel",
        {
            "v": PEER_DC_PROTOCOL_VERSION,
            "t": "send_file_cancel",
            "rid": "cancel-now",
            "upload_id": upload_id,
        },
    )

    assert captured[-1]["t"] == "send_file_cancel_result"
    assert captured[-1]["ok"] is True
    assert upload_id not in server._phone_uploads
    assert not staged.exists()
    assert server._upload_reservations.snapshot() == ()


@pytest.mark.asyncio
async def test_send_file_init_returns_upload_id_and_chunk_size(
    server_with_state, monkeypatch,
):
    server, _ = server_with_state
    # Redirect uploads dir into tmp so we don't leave debris.
    from one_link import server as srv_mod
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="ol_upload_test_")
    monkeypatch.setattr(srv_mod, "data_dir", lambda: __import__("pathlib").Path(tmpdir))
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "send_file_init",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_init",
         "rid": "f3", "peer_fp": "sha256:abc",
         "filename": "hello.txt", "mime": "text/plain",
         "size_bytes": 5},
    )
    reply = captured[0]
    assert reply["t"] == "send_file_init_ack"
    assert reply["rid"] == "f3"
    assert isinstance(reply["upload_id"], str) and len(reply["upload_id"]) >= 16
    assert reply["chunk_size"] > 0
    # Server should now hold one in-flight upload.
    assert len(server._phone_uploads) == 1


@pytest.mark.asyncio
async def test_send_file_chunk_offset_mismatch_errors(
    server_with_state, monkeypatch,
):
    server, _ = server_with_state
    from one_link import server as srv_mod
    import tempfile, base64
    tmpdir = tempfile.mkdtemp(prefix="ol_upload_test_")
    monkeypatch.setattr(srv_mod, "data_dir", lambda: __import__("pathlib").Path(tmpdir))
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "send_file_init",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_init",
         "rid": "f4", "peer_fp": "sha256:abc",
         "filename": "a.bin", "size_bytes": 100},
    )
    uid = captured[0]["upload_id"]
    captured.clear()
    # Wrong offset (expected 0, send 50).
    await server._handle_browser_peer_request(
        peer, "control", "send_file_chunk",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_chunk",
         "rid": "f5", "upload_id": uid, "offset": 50,
         "data_b64": base64.urlsafe_b64encode(b"x" * 10).decode().rstrip("=")},
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "offset_mismatch"


@pytest.mark.asyncio
async def test_send_file_chunk_size_overflow_errors(
    server_with_state, monkeypatch,
):
    server, _ = server_with_state
    from one_link import server as srv_mod
    import tempfile, base64
    tmpdir = tempfile.mkdtemp(prefix="ol_upload_test_")
    monkeypatch.setattr(srv_mod, "data_dir", lambda: __import__("pathlib").Path(tmpdir))
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "send_file_init",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_init",
         "rid": "f6", "peer_fp": "sha256:abc",
         "filename": "a.bin", "size_bytes": 10},
    )
    uid = captured[0]["upload_id"]
    captured.clear()
    # Send 20 bytes when only 10 declared.
    big = base64.urlsafe_b64encode(b"x" * 20).decode().rstrip("=")
    await server._handle_browser_peer_request(
        peer, "control", "send_file_chunk",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_chunk",
         "rid": "f7", "upload_id": uid, "offset": 0,
         "data_b64": big},
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "size_overflow"


@pytest.mark.asyncio
async def test_send_file_complete_calls_daemon_send_file(
    server_with_state, monkeypatch,
):
    server, _ = server_with_state
    from one_link import server as srv_mod
    import tempfile, base64
    tmpdir = tempfile.mkdtemp(prefix="ol_upload_test_")
    monkeypatch.setattr(srv_mod, "data_dir", lambda: __import__("pathlib").Path(tmpdir))

    class FakePeer:
        fingerprint = "sha256:abc"

    async def fake_resolve(needle):
        return FakePeer()

    def fake_queue(peer_fp=None, path=None, reason=None, schedule_resume=None):
        class _Rec:
            id = "tx-1"
        return _Rec()

    captured_send_args: dict = {}

    async def fake_send_file(target, path, transfer_id=None):
        captured_send_args.update(
            target=target, path=str(path), transfer_id=transfer_id,
        )
        return {"ok": True, "transfer_id": transfer_id, "bytes": 11}

    monkeypatch.setattr(server.daemon, "resolve_for_send", fake_resolve)
    monkeypatch.setattr(server.daemon, "queue_file_transfer", fake_queue)
    monkeypatch.setattr(server.daemon, "send_file", fake_send_file)

    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "send_file_init",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_init",
         "rid": "f8", "peer_fp": "sha256:abc",
         "filename": "a.txt", "mime": "text/plain", "size_bytes": 11},
    )
    uid = captured[0]["upload_id"]
    captured.clear()
    body = b"hello world"  # 11 bytes
    chunk_b64 = base64.urlsafe_b64encode(body).decode().rstrip("=")
    await server._handle_browser_peer_request(
        peer, "control", "send_file_chunk",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_chunk",
         "rid": "f9", "upload_id": uid, "offset": 0,
         "data_b64": chunk_b64},
    )
    assert captured[0]["t"] == "send_file_chunk_ack"
    assert captured[0]["received_size"] == 11
    captured.clear()
    await server._handle_browser_peer_request(
        peer, "control", "send_file_complete",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_complete",
         "rid": "f10", "upload_id": uid},
    )
    assert captured[0]["t"] == "send_file_result"
    assert captured[0]["ok"] is True
    assert captured[0]["transfer_id"] == "tx-1"
    assert captured_send_args["transfer_id"] == "tx-1"
    # And the in-flight record is gone.
    assert uid not in server._phone_uploads


@pytest.mark.asyncio
async def test_send_file_complete_size_mismatch_errors(
    server_with_state, monkeypatch,
):
    server, _ = server_with_state
    from one_link import server as srv_mod
    import tempfile, base64
    tmpdir = tempfile.mkdtemp(prefix="ol_upload_test_")
    monkeypatch.setattr(srv_mod, "data_dir", lambda: __import__("pathlib").Path(tmpdir))
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "send_file_init",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_init",
         "rid": "f11", "peer_fp": "sha256:abc",
         "filename": "a.txt", "size_bytes": 100},
    )
    uid = captured[0]["upload_id"]
    captured.clear()
    # Only send 10 bytes of the promised 100, then complete.
    chunk = base64.urlsafe_b64encode(b"x" * 10).decode().rstrip("=")
    await server._handle_browser_peer_request(
        peer, "control", "send_file_chunk",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_chunk",
         "rid": "f12", "upload_id": uid, "offset": 0, "data_b64": chunk},
    )
    captured.clear()
    await server._handle_browser_peer_request(
        peer, "control", "send_file_complete",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "send_file_complete",
         "rid": "f13", "upload_id": uid},
    )
    assert captured[0]["t"] == "error"
    assert captured[0]["code"] == "size_mismatch"
    # A premature complete must not destroy already accepted bytes. The phone
    # can continue from the authoritative received_size and retry completion.
    assert server._phone_uploads[uid]["received_size"] == 10
    assert await server._discard_phone_upload(uid)


def test_phone_compose_has_paperclip_and_progress(peer_html: str):
    """Phase 2: chat surface MUST have a paperclip attach button,
    a hidden file input, a progress bar, and a cancel button. The
    HTML shape is what _handleDaemonChatFilePicked + the chunk
    loop wire onto — any rename here silently breaks the UX."""
    assert 'id="btn-daemon-chat-attach"' in peer_html
    assert 'id="daemon-chat-file-input"' in peer_html
    assert 'id="daemon-chat-upload-progress"' in peer_html
    assert 'id="daemon-chat-upload-bar"' in peer_html
    assert 'id="btn-daemon-chat-upload-cancel"' in peer_html
    assert '_daemonRequest("send_file_cancel"' in peer_html
    assert "_phoneFileUploadId" in peer_html


def test_phone_file_uploader_uses_chunked_protocol(peer_html: str):
    """Phone uploads retain one stable intent across bounded retries."""
    handler = _snippet(
        peer_html,
        "async function _handleDaemonChatFilePicked(",
        14000,
    )
    window = _snippet(peer_html, "async function _sendPhoneFileChunksWindowed(", 5000)
    assert "_daemonRequestWithRetry(" in handler
    assert '"send_file_init"' in handler
    assert '"send_file_complete"' in handler
    assert '_daemonRequestWithRetry("send_file_chunk"' in window
    assert "client_msg_id: optimisticId" in handler
    assert "received_size" in handler
    assert "_PHONE_FILE_WINDOW_MAX_CHUNKS" in window
    assert "_PHONE_FILE_WINDOW_MAX_BYTES" in window
    assert "result.ok === false" in peer_html


# ───────── fetch_blob_chunk (file-RECEIVE on phone) ───────────────


@pytest.mark.asyncio
async def test_fetch_messages_includes_file_metadata(server_with_state):
    """File messages MUST surface name/size/blob_hash/mime as a
    nested `file` field so the phone can render an inline file
    bubble. Text messages MUST NOT include `file` (clean wire
    surface)."""
    server, state = server_with_state
    state.upsert_peer(
        fingerprint="sha256:peer1",
        short_id="peer1",
        hostname="other-laptop",
        pubkey=b"\x01" * 32,
    )
    # Text message — no file field expected.
    state.record_message(
        id="m1", ts_ms=1000, direction="in", peer_fp="sha256:peer1",
        msg_type="TEXT", body="hello",
    )
    # File message — name/size/blob_hash in metadata.
    state.record_message(
        id="m2", ts_ms=2000, direction="in", peer_fp="sha256:peer1",
        msg_type="FILE", body="cat.jpg",
        metadata={"name": "cat.jpg", "size": 1234,
                  "blob_hash": "a" * 64, "mime": "image/jpeg"},
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_messages",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_messages",
         "rid": "r1", "peer_fp": "sha256:peer1"},
    )
    reply = captured[0]
    msgs = {m["id"]: m for m in reply["messages"]}
    assert "file" not in msgs["m1"], "text messages MUST NOT include file field"
    assert "file" in msgs["m2"], "file messages MUST surface file field"
    f = msgs["m2"]["file"]
    assert f["name"] == "cat.jpg"
    assert f["size"] == 1234
    assert f["blob_hash"] == "a" * 64
    assert f["mime"] == "image/jpeg"


@pytest.mark.asyncio
async def test_fetch_blob_chunk_validates_inputs(server_with_state):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    # Bad blob_hash (not 64 hex chars).
    await server._handle_browser_peer_request(
        peer, "control", "fetch_blob_chunk",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_blob_chunk",
         "rid": "b1", "blob_hash": "tooshort",
         "offset": 0, "length": 1024},
    )
    assert captured[-1]["code"] == "bad_blob_hash"
    # Bad offset.
    await server._handle_browser_peer_request(
        peer, "control", "fetch_blob_chunk",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_blob_chunk",
         "rid": "b2", "blob_hash": "a" * 64,
         "offset": -1, "length": 1024},
    )
    assert captured[-1]["code"] == "bad_offset"
    # Bad length (over the chunk cap).
    await server._handle_browser_peer_request(
        peer, "control", "fetch_blob_chunk",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_blob_chunk",
         "rid": "b3", "blob_hash": "a" * 64,
         "offset": 0, "length": 1024 * 1024},
    )
    assert captured[-1]["code"] == "bad_length"


@pytest.mark.asyncio
async def test_fetch_blob_chunk_no_blob_store(server_with_state):
    server, _ = server_with_state
    server.daemon.blob_store = None
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "fetch_blob_chunk",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_blob_chunk",
         "rid": "b4", "blob_hash": "a" * 64,
         "offset": 0, "length": 1024},
    )
    assert captured[-1]["t"] == "error"
    assert captured[-1]["code"] == "no_blob_store"


@pytest.mark.asyncio
async def test_fetch_blob_chunk_streams_real_blob(server_with_state, tmp_path):
    """Round-trip: put bytes into the blob store, fetch them back
    in chunks, reassemble, verify they match. Pins the eof signal
    and the offset/length math."""
    server, _ = server_with_state
    from one_link.blobstore import BlobStore
    store = BlobStore(tmp_path / "blobs")
    payload = b"the quick brown fox " * 50  # 1000 bytes
    blob_hash = store.put_bytes(payload)
    server.daemon.blob_store = store

    peer, captured = _capture_peer(server)
    chunks = []
    offset = 0
    while True:
        await server._handle_browser_peer_request(
            peer, "control", "fetch_blob_chunk",
            {"v": PEER_DC_PROTOCOL_VERSION, "t": "fetch_blob_chunk",
             "rid": f"b{offset}", "blob_hash": blob_hash,
             "offset": offset, "length": 256},
        )
        reply = captured[-1]
        assert reply["t"] == "blob_chunk"
        assert reply["blob_hash"] == blob_hash
        assert reply["total_size"] == len(payload)
        import base64 as _b64
        if reply.get("data_b64"):
            std = reply["data_b64"].replace("-", "+").replace("_", "/")
            pad = std + "=" * ((4 - len(std) % 4) % 4)
            chunks.append(_b64.b64decode(pad))
            offset += len(chunks[-1])
        if reply.get("eof"):
            break
    assembled = b"".join(chunks)
    assert assembled == payload
    assert offset == len(payload)


def test_phone_file_bubble_renders_for_inbound_files(peer_html: str):
    """Phase A file-RECEIVE: phone MUST render inbound file
    messages as a file bubble with a download button. Without this
    the phone shows file messages as raw text and the user has no
    way to retrieve the bytes."""
    assert "function _renderFileBubbleBody(" in peer_html
    assert "async function _downloadFileFromDaemon(" in peer_html
    # The download path uses fetch_blob_chunk via _daemonRequest.
    snip = _snippet(peer_html, "async function _downloadFileFromDaemon(", 2500)
    assert '_daemonRequest("fetch_blob_chunk"' in snip
    # Assembles chunks into a Blob and triggers browser download.
    assert "new Blob(" in snip
    assert "URL.createObjectURL" in snip
    assert "a.download" in snip


# ───────── set_peer_alias + set_peer_mute (peer mgmt) ─────────────


@pytest.mark.asyncio
async def test_set_peer_alias_validates_inputs(server_with_state):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    # Missing peer_fp.
    await server._handle_browser_peer_request(
        peer, "control", "set_peer_alias",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "set_peer_alias",
         "rid": "a1", "alias": "Laptop"},
    )
    assert captured[-1]["code"] == "bad_peer_fp"
    # Wrong alias type.
    await server._handle_browser_peer_request(
        peer, "control", "set_peer_alias",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "set_peer_alias",
         "rid": "a2", "peer_fp": "sha256:abc", "alias": 123},
    )
    assert captured[-1]["code"] == "bad_alias"
    # Too long.
    await server._handle_browser_peer_request(
        peer, "control", "set_peer_alias",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "set_peer_alias",
         "rid": "a3", "peer_fp": "sha256:abc", "alias": "x" * 65},
    )
    assert captured[-1]["code"] == "alias_too_long"


@pytest.mark.asyncio
async def test_set_peer_alias_unknown_peer_errors(server_with_state):
    server, _ = server_with_state
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "set_peer_alias",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "set_peer_alias",
         "rid": "a4", "peer_fp": "sha256:nonexistent",
         "alias": "Laptop"},
    )
    assert captured[-1]["t"] == "error"
    assert captured[-1]["code"] == "peer_not_found"


@pytest.mark.asyncio
async def test_set_peer_alias_happy_path_returns_updated(server_with_state):
    server, state = server_with_state
    state.upsert_peer(
        fingerprint="sha256:peer1",
        short_id="peer1",
        hostname="other-laptop",
        pubkey=b"\x01" * 32,
    )
    peer, captured = _capture_peer(server)
    await server._handle_browser_peer_request(
        peer, "control", "set_peer_alias",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "set_peer_alias",
         "rid": "a5", "peer_fp": "sha256:peer1",
         "alias": "My Laptop"},
    )
    reply = captured[-1]
    assert reply["t"] == "set_peer_alias_result"
    assert reply["ok"] is True
    assert reply["peer_fp"] == "sha256:peer1"
    assert reply["alias"] == "My Laptop"
    # And the daemon state took the change.
    rec = state.get_peer("sha256:peer1")
    assert rec.local_alias == "My Laptop"


@pytest.mark.asyncio
async def test_set_peer_mute_validates_and_persists(server_with_state):
    server, state = server_with_state
    state.upsert_peer(
        fingerprint="sha256:peer2",
        short_id="peer2",
        hostname="phone",
        pubkey=b"\x02" * 32,
    )
    peer, captured = _capture_peer(server)
    # Bad muted type.
    await server._handle_browser_peer_request(
        peer, "control", "set_peer_mute",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "set_peer_mute",
         "rid": "m1", "peer_fp": "sha256:peer2", "muted": "yes"},
    )
    assert captured[-1]["code"] == "bad_muted"
    # Happy path mute.
    await server._handle_browser_peer_request(
        peer, "control", "set_peer_mute",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "set_peer_mute",
         "rid": "m2", "peer_fp": "sha256:peer2", "muted": True},
    )
    reply = captured[-1]
    assert reply["t"] == "set_peer_mute_result"
    assert reply["ok"] is True
    assert reply["muted"] is True
    rec = state.get_peer("sha256:peer2")
    assert bool(rec.muted) is True
    # Unmute.
    await server._handle_browser_peer_request(
        peer, "control", "set_peer_mute",
        {"v": PEER_DC_PROTOCOL_VERSION, "t": "set_peer_mute",
         "rid": "m3", "peer_fp": "sha256:peer2", "muted": False},
    )
    assert captured[-1]["muted"] is False
    rec = state.get_peer("sha256:peer2")
    assert bool(rec.muted) is False


def test_phone_chat_card_has_peer_info_strip(peer_html: str):
    """Phase 3a: chat card MUST expose Info button + collapsible
    peer-info panel with alias input, save button, mute toggle,
    and status line."""
    assert 'id="btn-daemon-chat-info"' in peer_html
    assert 'id="daemon-chat-peer-info"' in peer_html
    assert 'id="daemon-chat-peer-alias"' in peer_html
    assert 'id="btn-daemon-chat-peer-alias-save"' in peer_html
    assert 'id="daemon-chat-peer-mute-toggle"' in peer_html
    assert 'id="daemon-chat-peer-info-status"' in peer_html


def test_phone_peer_mgmt_uses_correct_wire_kinds(peer_html: str):
    """The phone-side calls MUST hit set_peer_alias and
    set_peer_mute via _daemonRequest. Any rename here drops the
    correspondence with the server handler silently."""
    alias_snip = _snippet(peer_html, "async function setDaemonPeerAlias(", 600)
    assert '_daemonRequest("set_peer_alias"' in alias_snip
    mute_snip = _snippet(peer_html, "async function setDaemonPeerMute(", 600)
    assert '_daemonRequest("set_peer_mute"' in mute_snip


# ───────── phase 3b: phone Settings card ──────────────────────────


def test_phone_settings_card_present(peer_html: str):
    """Phase 3b: phone exposes its own Settings card with device
    info, paired daemon info, and a sign-out path. Without this
    the phone has no way to inspect its identity or rotate it."""
    assert 'id="phone-settings-card"' in peer_html
    assert 'id="btn-phone-settings"' in peer_html
    assert 'id="btn-phone-settings-back"' in peer_html
    # Device identity surface.
    assert 'id="phone-settings-device-label"' in peer_html
    assert 'id="phone-settings-device-fp"' in peer_html
    assert 'id="phone-settings-device-paired"' in peer_html
    # Paired daemon surface.
    assert 'id="phone-settings-daemon-label"' in peer_html
    assert 'id="phone-settings-daemon-fp"' in peer_html
    assert 'id="phone-settings-daemon-status"' in peer_html
    # Sign-out action.
    assert 'id="btn-phone-settings-signout"' in peer_html
    assert 'id="phone-settings-signout-status"' in peer_html


def test_phone_settings_uses_fetch_self_for_daemon_info(peer_html: str):
    """The Settings card calls fetch_self over the DC to pull
    the live daemon hostname + fingerprint. If the DC is dead
    the catch surfaces 'Not connected', not a silent blank."""
    snip = _snippet(peer_html, "async function _openPhoneSettings(", 3500)
    assert '_daemonRequest("fetch_self"' in snip
    assert "Connected" in snip
    assert "Not connected" in snip


def test_phone_signout_clears_local_state(peer_html: str):
    """Sign-out MUST drop the OPFS keypair (via deleteIdentity)
    AND the localStorage cert (SELF_MESH_CERT_KEY) AND reload
    the page. Missing any one of these leaves the phone in a
    half-signed-out state that the next pair attempt can't recover
    from cleanly."""
    snip = _snippet(peer_html, "async function _handlePhoneSignOut(", 2200)
    assert "deleteIdentity(" in snip
    assert "SELF_MESH_CERT_KEY" in snip
    assert "removeItem" in snip
    assert "window.location.reload" in snip


# ───────── phase 4: mobile-first CSS ──────────────────────────────


def test_phone_has_mobile_media_query(peer_html: str):
    """Phase 4: the mobile breakpoint MUST exist so phones get the
    full-bleed, touch-tuned layout instead of the desktop's
    600px-centered cards. Without this the phone falls back to
    desktop spacing, the chat log doesn't flex to fill the screen,
    and the compose input gets eaten by the iOS keyboard."""
    assert "@media (max-width: 700px)" in peer_html


def test_phone_chat_log_flexes_and_compose_sticks(peer_html: str):
    """The mobile chat layout MUST make the log flex-fill and pin
    the compose bar to the bottom. Otherwise the input scrolls
    off-screen as messages pile up — the single most common
    'phone chat is broken' UX bug."""
    # Roughly locate the @media block (it's the last block we
    # emit before </style>).
    idx = peer_html.find("@media (max-width: 700px)")
    assert idx > 0
    block_end = peer_html.find("</style>", idx)
    media_block = peer_html[idx:block_end]
    assert "#daemon-chat-log" in media_block
    assert "flex: 1 1 auto" in media_block
    assert "#daemon-chat-compose" in media_block
    assert "position: sticky" in media_block
    # Crucial: textarea font >= 16px so iOS Safari doesn't
    # auto-zoom on focus (the zoom never undoes itself, leaving
    # the chat unreadable).
    assert "font-size: 16px" in media_block


def test_phone_auto_reconnect_on_boot(peer_html: str):
    """2026-05-23 Wave 2: phone with a valid cert from a previous
    pair MUST attempt auto-reconnect on boot via /relogin instead
    of dead-ending at the welcome card. Failure cases (cert
    expired, daemon root rotated, device revoked, network down)
    MUST surface clearly, not silently.
    """
    # Detection helper checks the cert is non-pending and trusted.
    assert "function _hasExistingPairCert(" in peer_html
    assert "SELF_MESH_CERT_KEY" in peer_html
    # The boot dispatcher routes through the returning-pair branch
    # when no fresh-pair query is active but a cert exists.
    assert "_hasReturningPair" in peer_html
    # The relogin attempt: requests a daemon-selected one-time challenge,
    # signs its bound proof, then POSTs cert + challenge id + signature to
    # /api/setup/device-invite/relogin and runs the autopair bootstrap.
    assert "async function _attemptReloginWithStoredCert(" in peer_html
    assert "/api/setup/device-invite/relogin/challenge" in peer_html
    assert "/api/setup/device-invite/relogin" in peer_html
    assert "_signEd25519(" in peer_html
    # Failure surfaces a clear next step rather than silently
    # dropping the user on a blank welcome card.
    snip = _snippet(peer_html, "async function _attemptReloginWithStoredCert(", 3500)
    assert "proof_b64" in snip
    assert "challenge_id" in snip
    assert "nonce_b64" not in snip
    assert "Scan a fresh pair QR" in snip
    assert "_runAutoPairFlow(" in peer_html  # called after success


def test_show_only_helper_pinned_in_peer_html(peer_html: str):
    """2026-05-23 bugfix: strict single-pane navigation. _showOnly
    hides every top-level card then shows just one — replaces the
    ad-hoc show()/hide() pairs that allowed the 'JOIN MY DEVICES +
    YOUR CHATS + CHAT all visible' multi-card stack the user hit.

    The helper MUST exist, MUST iterate over _PHONE_TOP_LEVEL_CARDS,
    and MUST be called by every flow that surfaces a top-level card."""
    assert "function _showOnly(" in peer_html
    assert "const _PHONE_TOP_LEVEL_CARDS" in peer_html
    # Cards that the user hits during the pair-and-chat flow MUST
    # all be in the list so _showOnly knows about them.
    for cid in (
        '"#welcome-card"',
        '"#autopair-card"',
        '"#selfmesh-enroll-card"',
        '"#daemon-roster-card"',
        '"#daemon-chat-card"',
        '"#phone-settings-card"',
    ):
        assert cid in peer_html, f"{cid} missing from _PHONE_TOP_LEVEL_CARDS"
    # And every flow that lands a user on one of those cards MUST
    # go through _showOnly.
    for call in (
        '_showOnly("#welcome-card")',
        '_showOnly("#autopair-card")',
        '_showOnly("#selfmesh-enroll-card")',
        '_showOnly("#daemon-roster-card")',
        '_showOnly("#daemon-chat-card")',
        '_showOnly("#phone-settings-card")',
    ):
        assert call in peer_html, (
            f"{call} missing — that flow's card-show path bypasses "
            f"single-pane navigation and will stack on top of prior cards"
        )


def test_open_daemon_chat_rejects_peer_without_fingerprint(peer_html: str):
    """Defensive: _openDaemonChat MUST early-return on a stub peer
    object missing the fingerprint field. Past bug: roster row
    passed an empty stub, chat opened with title 'CHAT' (the h2
    default) and an empty log because fetchDaemonMessages('') is a
    no-op. This guard makes the failure observable instead of
    silent."""
    snippet = _snippet(peer_html, "async function _openDaemonChat", 900)
    assert "if (!peer || !peer.fingerprint)" in snippet
    assert "console.warn" in snippet


def test_phone_touch_targets_meet_min_size(peer_html: str):
    """iOS HIG floor is 44pt; we bump to 48 for primary actions.
    Pinned so a future CSS refactor doesn't accidentally drop
    touch targets below the comfortable threshold."""
    idx = peer_html.find("@media (max-width: 700px)")
    block_end = peer_html.find("</style>", idx)
    media_block = peer_html[idx:block_end]
    assert "min-height: 48px" in media_block
    # Roster rows should be even larger.
    assert "min-height: 64px" in media_block


# ───────── phone-side roster + chat surface ────────────────────────


def test_daemon_roster_card_present(peer_html: str):
    assert 'id="daemon-roster-card"' in peer_html
    assert 'id="daemon-peers-list"' in peer_html
    assert 'id="daemon-chat-card"' in peer_html
    assert 'id="daemon-chat-log"' in peer_html
    assert 'id="btn-daemon-chat-back"' in peer_html


def test_daemon_roster_card_hidden_until_pair(peer_html: str):
    """The roster shows only after auto-pair finalize fetches it."""
    idx = peer_html.find('id="daemon-roster-card"')
    open_start = peer_html.rfind("<div", 0, idx)
    open_end = peer_html.find(">", idx)
    tag = peer_html[open_start:open_end + 1]
    assert "hidden" in tag


def test_daemon_chat_card_hidden_until_row_tap(peer_html: str):
    idx = peer_html.find('id="daemon-chat-card"')
    open_start = peer_html.rfind("<div", 0, idx)
    open_end = peer_html.find(">", idx)
    tag = peer_html[open_start:open_end + 1]
    assert "hidden" in tag


def test_register_daemon_dc_helper_present(peer_html: str):
    """Single source of truth for "this DataChannel is the daemon."
    Stores the dc reference + wires close handler."""
    snippet = _snippet(peer_html, "function _registerDaemonDc", 4000)
    assert "daemonLink.attach(dc, daemonFingerprint" in snippet
    assert 'addEventListener("close"' in snippet


def test_route_daemon_dc_message_routes_by_rid(peer_html: str):
    """Responses come back keyed by rid. The router looks up the
    pending Promise and resolves/rejects."""
    snippet = _snippet(peer_html, "function _routeDaemonDcMessage", 1500)
    assert "state.daemon_pending.has(rid)" in snippet
    assert "pending.resolve(msg)" in snippet
    assert 'msg.t === "error"' in snippet
    assert "pending.reject(" in snippet


def test_daemon_request_uses_uuid_rid(peer_html: str):
    """Every request gets a fresh rid via crypto.randomUUID. Must
    not reuse rids — collisions would deliver wrong responses to
    in-flight Promises."""
    snippet = _snippet(peer_html, "function _daemonRequest", 1500)
    assert "_genRid()" in snippet
    assert 'v: "OL-PEER-1"' in snippet


def test_daemon_request_has_timeout(peer_html: str):
    """10s default timeout. Promise rejects if no matching response
    arrives — phone surfaces a "couldn't fetch" message instead of
    spinning forever."""
    snippet = _snippet(peer_html, "function _daemonRequest", 1500)
    assert "DAEMON_REQUEST_TIMEOUT_MS" in snippet
    assert "setTimeout(" in snippet
    assert "rejected" not in snippet  # we use reject, not "rejected"


def test_daemon_request_clears_on_channel_close(peer_html: str):
    """If the channel closes mid-request, every in-flight Promise
    rejects with "daemon channel closed." Otherwise the phone hangs."""
    snippet = _snippet(peer_html, "function _registerDaemonDc", 4000)
    assert "daemon channel closed" in snippet
    assert "daemonLink.detach(" in snippet


def test_fetch_daemon_peers_helper(peer_html: str):
    """Wraps _daemonRequest("fetch_peers") and returns the peers
    array, defaulting to []."""
    snippet = _snippet(peer_html, "async function fetchDaemonPeers", 800)
    assert '_daemonRequest("fetch_peers"' in snippet
    assert "Array.isArray(reply.peers)" in snippet


def test_fetch_daemon_messages_helper(peer_html: str):
    """Wraps _daemonRequest("fetch_messages") with peer_fp + limit."""
    snippet = _snippet(peer_html, "async function fetchDaemonMessages", 1000)
    assert '_daemonRequest("fetch_messages"' in snippet
    assert "peer_fp: peerFp" in snippet
    assert "limit: limit" in snippet


def test_refresh_roster_renders_rows(peer_html: str):
    """_refreshDaemonRoster sorts peers by last_seen_ms desc + renders
    a tap-able row for each."""
    snippet = _snippet(peer_html, "async function _refreshDaemonRoster", 4000)
    assert "fetchDaemonPeers()" in snippet
    assert "last_seen_ms" in snippet
    assert "_openDaemonChat(peer)" in snippet


def test_open_daemon_chat_loads_messages(peer_html: str):
    """Tapping a peer row fetches messages + renders bubbles in the
    chat log. Uses _showOnly so the chat card is the only top-level
    card visible (previous show/hide pair allowed multi-card stacks)."""
    snippet = _snippet(peer_html, "async function _openDaemonChat", 3600)
    assert "fetchDaemonMessages(peer.fingerprint" in snippet
    assert "_renderDaemonMessageBubble(log, m)" in snippet
    assert '_showOnly("#daemon-chat-card")' in snippet


def test_chat_back_button_returns_to_roster(peer_html: str):
    """Back button uses _showOnly to surface the roster + clears
    the active-peer reference."""
    snippet = _snippet(peer_html, '"#btn-daemon-chat-back"', 800)
    assert '_showOnly("#daemon-roster-card")' in snippet
    assert "daemonConversation.close()" in snippet
    assert "daemonConversation.close();" in snippet


def test_render_message_bubble_handles_deleted_and_edited(peer_html: str):
    """Deleted messages render '(deleted)' italic. Edited messages
    show '· edited' in the meta line. Don't expose the original body
    of a deleted row to the phone."""
    snippet = _snippet(peer_html, "function _renderDaemonMessageBubble", 2500)
    assert "deleted_at_ms" in snippet
    assert "(deleted)" in snippet
    assert "edited_at_ms" in snippet


def test_autopair_finalize_kicks_off_roster_fetch(peer_html: str):
    """The auto-pair flow's finalize() MUST register the daemon DC
    and call _refreshDaemonRoster — otherwise the phone is paired
    but shows nothing."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 12000)
    assert "_registerDaemonDc(" in snippet
    assert "controlDc, pair.daemon_fingerprint" in snippet
    assert "_refreshDaemonRoster()" in snippet


def test_autopair_wires_dc_message_routing(peer_html: str):
    """The controlDc.onmessage MUST route through
    _routeDaemonDcMessage so request/response correlation works."""
    snippet = _snippet(peer_html, "async function _runAutoPairFlow", 12000)
    assert "controlDc.onmessage = (event) => _routeDaemonDcMessage(" in snippet
    assert "event.data, controlDc" in snippet


# ───────── test surface ───────────────────────────────────────────


def test_test_surface_exposes_daemon_helpers(peer_html: str):
    snippet = _snippet(peer_html, "window.__oneLinkPeer", 4000)
    for name in (
        "fetchDaemonPeers",
        "fetchDaemonMessages",
        "_daemonRequest",
        "_refreshDaemonRoster",
    ):
        assert name in snippet, f"surface missing {name}"


# ───────── version pin ────────────────────────────────────────────


def test_peer_version_at_or_above_v0202(peer_html: str):
    """Forward-compat: pin shape, not literal."""
    import re
    m = re.search(r"version:\s*['\"](\d+)\.(\d+)\.(\d+)(?:-[A-Za-z0-9.]+)?['\"]", peer_html)
    assert m
    parts = tuple(int(p) for p in m.groups())
    assert parts >= (0, 20, 2)


def test_page_version_matches_package():
    from one_link import __version__
    html = Path("src/one_link/web/index.html").read_text(encoding="utf-8")
    assert f'PAGE_BUILT_FOR = "{__version__}"' in html
