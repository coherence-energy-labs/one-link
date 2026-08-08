"""v0.8.0 group UI tests.

Pin the contract:
  - Daemon.create_group: signs CREATE + ADD_MEMBER events,
    persists, fans out via _broadcast_group_event, caches group
    name in group_meta. Returns {group_id, name, member_count}.
  - Daemon.add_group_member / remove_group_member work end-to-end
    against the CRDT.
  - Inbound GROUP_EVENT handler: pinned-only, signature-verified,
    persisted via state.upsert_group_event.
  - Server endpoints: list / create / get / messages / send / add /
    remove all wire correctly + JSON-serialize bytes properly.
  - HTML structural pin: groups sidebar section, create-group
    modal, helper functions, WS group_event handler.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from one_link.daemon import Daemon
from one_link.identity import Identity, fingerprint_of
from one_link.state import State
from one_link.wire import decode_msg, make_msg


def _new_identity() -> Identity:
    sk = Ed25519PrivateKey.generate()
    pub_obj = sk.public_key()
    pub_bytes = pub_obj.public_bytes_raw()
    fp = fingerprint_of(pub_bytes)
    return Identity(
        private=sk, public=pub_obj, public_bytes=pub_bytes,
        fingerprint=fp, short_id=fp[:8], hostname="x",
    )


class _FakeChannel:
    def __init__(self, *, peer_ed_pub: bytes, peer_short_id: str):
        self.peer_ed_pub = peer_ed_pub
        self.peer_short_id = peer_short_id
        self.peer_caps: dict | None = None
        self.sent: list[dict] = []

    async def send(self, payload: bytes) -> None:
        self.sent.append(decode_msg(payload))

    async def recv(self) -> bytes:
        raise NotImplementedError

    async def close(self) -> None:
        pass


# ─── Daemon.create_group ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_create_group_persists_events(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")

    # No discovery; resolve_for_send returns None → fan-out is a no-op
    # but the events still persist locally.
    async def _no_resolve(needle):
        return None
    daemon.resolve_for_send = _no_resolve  # type: ignore[method-assign]

    result = await daemon.create_group(
        name="Test Group", member_pubkeys=[them.public_bytes],
    )
    assert result["name"] == "Test Group"
    assert result["member_count"] == 2  # me + them

    # Two events persisted: CREATE + ADD_MEMBER.
    gid = bytes.fromhex(result["group_id"])
    events = state.list_group_events(gid)
    kinds = {e["kind"] for e in events}
    assert "create" in kinds
    assert "add_member" in kinds
    state.close()


@pytest.mark.asyncio
async def test_create_group_caches_name_in_meta(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state

    async def _no_resolve(needle):
        return None
    daemon.resolve_for_send = _no_resolve  # type: ignore[method-assign]

    result = await daemon.create_group(name="Solo", member_pubkeys=[])
    gid = bytes.fromhex(result["group_id"])
    meta = state.get_group_meta(gid)
    assert meta is not None
    assert meta.get("name") == "Solo"
    state.close()


@pytest.mark.asyncio
async def test_create_group_skips_self_in_member_list(tmp_path: Path):
    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state

    async def _no_resolve(needle):
        return None
    daemon.resolve_for_send = _no_resolve  # type: ignore[method-assign]

    result = await daemon.create_group(
        name="Test", member_pubkeys=[me.public_bytes],
    )
    # Genesis CREATE adds me as owner, ADD_MEMBER for self is skipped.
    assert result["member_count"] == 1
    state.close()


# ─── Inbound GROUP_EVENT handler ──────────────────────────────────

@pytest.mark.asyncio
async def test_inbound_group_event_pinned_persists(tmp_path: Path):
    """Two daemons: alice creates a group; bob receives the event."""
    alice = _new_identity()
    bob = _new_identity()

    # Alice's state has the group.
    a_state = State(db_path=tmp_path / "a.db")
    a_daemon = Daemon(alice)
    a_daemon.state = a_state

    async def _no_resolve(needle):
        return None
    a_daemon.resolve_for_send = _no_resolve  # type: ignore[method-assign]

    a_state.upsert_peer(
        fingerprint=bob.fingerprint, short_id=bob.short_id,
        pubkey=bob.public_bytes,
    )
    a_state.set_peer_trust(bob.fingerprint, "pinned")
    res = await a_daemon.create_group(name="Test", member_pubkeys=[bob.public_bytes])
    gid = bytes.fromhex(res["group_id"])

    # Now Bob's daemon receives the events.
    b_state = State(db_path=tmp_path / "b.db")
    b_daemon = Daemon(bob)
    b_daemon.state = b_state
    b_state.upsert_peer(
        fingerprint=alice.fingerprint, short_id=alice.short_id,
        pubkey=alice.public_bytes,
    )
    b_state.set_peer_trust(alice.fingerprint, "pinned")

    chan = _FakeChannel(
        peer_ed_pub=alice.public_bytes,
        peer_short_id=alice.short_id,
    )
    for ev_wire in a_state.list_group_events(gid):
        msg = make_msg("GROUP_EVENT", alice.short_id, event=ev_wire)
        await b_daemon._on_peer_message(chan, msg)
        assert chan.sent[-1].get("durable") is True
        assert not chan.sent[-1].get("rejected")

    # Bob now sees the same group + same events.
    bob_events = b_state.list_group_events(gid)
    assert len(bob_events) == len(a_state.list_group_events(gid))
    a_state.close()
    b_state.close()


@pytest.mark.asyncio
async def test_inbound_group_event_non_pinned_gets_negative_receipt(tmp_path: Path):
    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    # NOT pinned.
    chan = _FakeChannel(
        peer_ed_pub=them.public_bytes, peer_short_id=them.short_id,
    )
    # Forge any old event-shaped dict; the handler short-circuits on
    # _is_pinned before it gets to verify.
    msg = make_msg("GROUP_EVENT", them.short_id, event={"kind": "create"})
    await daemon._on_peer_message(chan, msg)
    # No state mutation, but the sender receives a terminal negative receipt
    # rather than timing out and retrying forever.
    assert state.list_group_ids() == []
    assert chan.sent[-1]["rejected"] == "peer_not_pinned"
    state.close()


@pytest.mark.asyncio
async def test_inbound_group_event_persist_failure_never_acks_or_broadcasts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
):
    from one_link import groups as gmod

    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = Daemon(me)
    daemon.state = state
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    event = gmod.sign_create_group(
        private_key=them.private, pubkey=them.public_bytes, name="Durable",
    )
    broadcasts: list[dict] = []
    daemon.ui_server = SimpleNamespace(broadcast=broadcasts.append)
    monkeypatch.setattr(
        state, "upsert_group_event",
        lambda **_kwargs: (_ for _ in ()).throw(OSError("disk full")),
    )
    chan = _FakeChannel(
        peer_ed_pub=them.public_bytes, peer_short_id=them.short_id,
    )
    msg = make_msg("GROUP_EVENT", them.short_id, event=event.to_wire())

    await daemon._on_peer_message(chan, msg)

    assert chan.sent[-1]["rejected"] == "message_persistence_failed"
    assert chan.sent[-1].get("durable") is not True
    assert broadcasts == []
    state.close()


# ─── Server endpoints ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_api_list_groups_empty(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(
        state=state,
        me=SimpleNamespace(
            fingerprint=me.fingerprint, short_id=me.short_id,
            hostname="me", public_bytes=me.public_bytes,
        ),
    )
    server = UIServer(daemon)

    class _Req:
        query: dict = {}
        match_info: dict = {}

    resp = await server.api_list_groups(_Req())
    body = json.loads(resp.text)
    assert body["groups"] == []
    state.close()


@pytest.mark.asyncio
async def test_api_create_group_validates_name(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(state=state, me=me)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info: dict = {}
        async def json(self):
            return {"name": "", "members": []}

    resp = await server.api_create_group(_Req())
    assert resp.status == 400
    state.close()


@pytest.mark.asyncio
async def test_api_create_group_rejects_unpinned_member(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    # NOT pinned.
    daemon = SimpleNamespace(state=state, me=me)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info: dict = {}
        async def json(self):
            return {"name": "Test", "members": [them.fingerprint]}

    resp = await server.api_create_group(_Req())
    assert resp.status == 400
    body = json.loads(resp.text)
    assert "paired" in body["error"] or "pinned" in body["error"]
    state.close()


@pytest.mark.asyncio
async def test_api_create_group_requires_two_other_devices(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    them = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    state.upsert_peer(
        fingerprint=them.fingerprint, short_id=them.short_id,
        pubkey=them.public_bytes,
    )
    state.set_peer_trust(them.fingerprint, "pinned")
    daemon = SimpleNamespace(state=state, me=me)
    server = UIServer(daemon)
    server.broadcast = lambda evt: None

    class _Req:
        match_info: dict = {}
        async def json(self):
            return {"name": "Too small", "members": [them.fingerprint]}

    resp = await server.api_create_group(_Req())
    body = json.loads(resp.text)
    assert resp.status == 400
    assert "at least 3 people" in body["error"]
    state.close()


@pytest.mark.asyncio
async def test_api_get_group_404_unknown(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(state=state, me=me)
    server = UIServer(daemon)

    class _Req:
        match_info = {"gid": "00" * 16}
        query: dict = {}

    resp = await server.api_get_group(_Req())
    assert resp.status == 404
    state.close()


@pytest.mark.asyncio
async def test_api_rename_group_calls_daemon_for_admin(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    gid = bytes.fromhex("ab" * 16)

    class _Daemon:
        def __init__(self):
            self.state = state
            self.me = SimpleNamespace(
                fingerprint=me.fingerprint,
                short_id=me.short_id,
                public_bytes=me.public_bytes,
            )
            self.renamed = None

        async def rename_group(self, *, group_id, name):
            self.renamed = (group_id, name)
            return {"name": name, "delivered": 0, "failures": []}

    daemon = _Daemon()
    server = UIServer(daemon)
    server._materialize_group = lambda _gid: {
        "group_id": gid.hex(),
        "name": "Old",
        "is_member": True,
        "my_role": "admin",
    }

    class _Req:
        match_info = {"gid": gid.hex()}
        async def json(self):
            return {"name": "New Name"}

    resp = await server.api_rename_group(_Req())
    body = json.loads(resp.text)
    assert resp.status == 200
    assert body["ok"] is True
    assert daemon.renamed == (gid, "New Name")
    state.close()


@pytest.mark.asyncio
async def test_api_group_messages_serializes_bytes_to_hex(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    # Insert a group_message row directly with bytes sender_pub.
    gid = b"\xab" * 16
    pub = b"\xcc" * 32
    state.insert_group_message(
        id="m1", group_id=gid, sender_pub=pub,
        epoch=1, counter=0, direction="in",
        body="hello group", reply_to="parent", ts_ms=1000,
    )
    daemon = SimpleNamespace(state=state, me=me)
    server = UIServer(daemon)

    class _Req:
        match_info = {"gid": gid.hex()}
        query: dict = {}

    resp = await server.api_group_messages(_Req())
    body = json.loads(resp.text)
    assert len(body["messages"]) == 1
    m = body["messages"][0]
    # sender_pub turned into hex string.
    assert m["sender_pub_hex"] == pub.hex()
    assert m["body"] == "hello group"
    assert m["reply_to"] == "parent"
    assert m["group_id"] == gid.hex()
    state.close()


@pytest.mark.asyncio
async def test_api_send_group_validates_body(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(state=state, me=me)
    server = UIServer(daemon)

    class _Req:
        match_info = {"gid": "ab" * 16}
        async def json(self):
            return {"body": ""}

    resp = await server.api_send_group(_Req())
    assert resp.status == 400
    state.close()


@pytest.mark.asyncio
async def test_api_send_group_threads_reply_to(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")

    class _Daemon:
        def __init__(self):
            self.state = state
            self.me = SimpleNamespace(
                fingerprint=me.fingerprint,
                short_id=me.short_id,
                hostname="me",
                public_bytes=me.public_bytes,
            )
            self.sent = None

        async def send_group_message(self, *, group_id, body, reply_to=None):
            self.sent = (group_id, body, reply_to)
            return {"msg_id": "m2"}

    daemon = _Daemon()
    server = UIServer(daemon)

    class _Req:
        match_info = {"gid": "ab" * 16}
        async def json(self):
            return {"body": "reply", "reply_to": "m1"}

    resp = await server.api_send_group(_Req())
    body = json.loads(resp.text)
    assert resp.status == 200
    assert body["ok"] is True
    assert daemon.sent == (bytes.fromhex("ab" * 16), "reply", "m1")
    state.close()


@pytest.mark.asyncio
async def test_api_leave_group_removes_self(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")

    class _Daemon:
        def __init__(self):
            self.state = state
            self.me = SimpleNamespace(
                fingerprint=me.fingerprint,
                short_id=me.short_id,
                hostname="me",
                public_bytes=me.public_bytes,
            )
            self.removed = None

        async def remove_group_member(self, *, group_id, member_pubkey):
            self.removed = (group_id, member_pubkey)
            return {"group_id": group_id.hex(), "member_count": 0}

    daemon = _Daemon()
    server = UIServer(daemon)

    class _Req:
        match_info = {"gid": "ab" * 16}

    resp = await server.api_leave_group(_Req())
    body = json.loads(resp.text)
    assert resp.status == 200
    assert body["ok"] is True
    assert daemon.removed == (bytes.fromhex("ab" * 16), me.public_bytes)
    state.close()


@pytest.mark.asyncio
async def test_api_group_message_actions_call_daemon(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    gid = bytes.fromhex("ab" * 16)
    state.insert_group_message(
        id="m1", group_id=gid, sender_pub=me.public_bytes,
        epoch=1, counter=0, direction="out", body="hello", ts_ms=1000,
    )

    class _Daemon:
        def __init__(self):
            self.state = state
            self.me = SimpleNamespace(
                fingerprint=me.fingerprint,
                short_id=me.short_id,
                public_bytes=me.public_bytes,
            )
            self.calls = []

        async def send_group_reaction(self, *, group_id, target_msg_id, emoji, op):
            self.calls.append(("react", group_id, target_msg_id, emoji, op))
            return {"delivered": 1}

        async def send_group_edit(self, *, group_id, target_msg_id, new_body):
            self.calls.append(("edit", group_id, target_msg_id, new_body))
            return {"delivered": 1}

        async def send_group_delete(self, *, group_id, target_msg_id):
            self.calls.append(("delete", group_id, target_msg_id))
            return {"delivered": 1}

    daemon = _Daemon()
    server = UIServer(daemon)

    class _ReactReq:
        match_info = {"gid": gid.hex(), "msg_id": "m1"}
        async def json(self):
            return {"emoji": "+1", "op": "add"}

    class _EditReq:
        match_info = {"gid": gid.hex(), "msg_id": "m1"}
        async def json(self):
            return {"body": "updated"}

    class _DeleteReq:
        match_info = {"gid": gid.hex(), "msg_id": "m1"}

    react = await server.api_react_group_message(_ReactReq())
    edit = await server.api_edit_group_message(_EditReq())
    delete = await server.api_delete_group_message(_DeleteReq())
    assert react.status == 200
    assert edit.status == 200
    assert delete.status == 200
    assert daemon.calls == [
        ("react", gid, "m1", "+1", "add"),
        ("edit", gid, "m1", "updated"),
        ("delete", gid, "m1"),
    ]
    state.close()


@pytest.mark.asyncio
async def test_api_group_invite_link_is_signed(tmp_path: Path):
    from one_link.server import UIServer

    me = _new_identity()
    state = State(db_path=tmp_path / "s.db")
    daemon = SimpleNamespace(state=state, me=me)
    server = UIServer(daemon)
    gid = bytes.fromhex("ab" * 16)
    server._materialize_group = lambda _gid: {
        "group_id": gid.hex(),
        "name": "Team",
        "is_member": True,
    }

    class _Req:
        match_info = {"gid": gid.hex()}
        query: dict = {}

    resp = await server.api_group_invite_link(_Req())
    body = json.loads(resp.text)
    assert resp.status == 200
    assert body["ok"] is True
    assert body["url"].startswith("one-link://group-invite/")
    assert body["issuer_fp"] == me.fingerprint
    state.close()


# ─── HTML structural pin ───────────────────────────────────────────

def test_index_html_has_groups_surface():
    p = (
        Path(__file__).resolve().parent.parent
        / "src" / "one_link" / "web" / "index.html"
    )
    text = p.read_text(encoding="utf-8")
    for needle in [
        'id="grouplist"',
        'id="groups-count"',
        'id="open-create-group"',
        'id="create-group-backdrop"',
        'id="cg-name"',
        'id="cg-members"',
        'id="cg-create"',
        "Pick at least two paired devices",
        "Groups need at least 3 people total",
        'id="btn-group-settings"',
        'id="group-settings-backdrop"',
        'id="group-settings-members"',
        'id="group-rename-input"',
        'id="group-rename-save"',
        'id="group-add-peer"',
        'id="group-add-member"',
        'id="group-copy-invite"',
        'id="group-leave"',
        "function refreshGroups",
        "function renderGroups",
        "function selectGroup",
        "function renderGroupConversation",
        "function renderGroupReplyQuote",
        "function renameCurrentGroup",
        "function togglePin",
        "function restoreDraft",
        'id="pin-strip"',
        '"group_reaction"',
        '"group_msg_edit"',
        '"group_msg_delete"',
        "function openGroupSettings",
        "function copyGroupInviteLink",
        "function leaveCurrentGroup",
        "function openCreateGroupModal",
        "function submitCreateGroup",
        '"group_event"',
        '"group_created"',
        ".grouplist",
        ".group-avatar",
        ".group-sender",
    ]:
        assert needle in text, f"index.html missing {needle!r}"


def test_the_group_invite_LINK_now_HAS_a_consumer():
    """This test used to assert the opposite, and inverting it was the point.

    The daemon minted `one-link://group-invite/<token>` for a long time while
    `peer_path_for_deep_link` answered "unsupported one-link route" -- a signed, copyable,
    shareable link with no consumer on ANY surface. That gap was pinned here deliberately so it
    could not be mistaken for a working feature, with a note that the pin would flip when
    redemption landed. It landed; this is the flip.

    Verification itself lives in `test_group_invite_verification.py`, forgery-first. What this
    asserts is narrower and is the regression that started it: the app ACCEPTS the URL it MINTS.
    """
    from one_link.protocol_handler import peer_path_for_deep_link

    # The route that was already wired, as a control: without it this test would also pass
    # against a handler that had started accepting everything.
    assert peer_path_for_deep_link(
        "one-link://self-mesh/enroll?token=" + "a" * 32
    ).startswith("/peer?")

    path = peer_path_for_deep_link("one-link://group-invite/" + "b" * 40)
    assert path.startswith("/peer?") and "group_invite=" in path

    # ...and a malformed token is still refused AT THE DOOR, before any decoder sees it.
    with pytest.raises(ValueError, match="group invite token is malformed"):
        peer_path_for_deep_link("one-link://group-invite/short!!")
